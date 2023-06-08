// use std::net::{TcpStream};
use std::os::unix::net::UnixStream;
use std::io::{
    Read, 
    Write
};
use std::process;
use vm_memory::{GuestMemoryMmap, GuestAddress, Bytes};
use logger::log_jaeger_warning;

pub const INIT:u64 = 0;
pub const INIT_COMPLETE:u64 = 1;
pub const EXEC:u64 = 2;
pub const EXIT:u64 = 3;
pub const MODIFY:u64 = 4;
pub const UNMODIFY:u64 = 5;
pub const SNAPSHOT: u64 = 6;
pub const FUZZ:u64 = 7;

pub const HANDLED:u64 = 0;
pub const STOPPED:u64 = 1;
pub const CRASHED:u64 = 2;

const PAGESHIFT: u32 = 12;
const PTSHIFT: u32 = PAGESHIFT;
const PDSHIFT: u32 = PTSHIFT + 9;
const PDPSHIFT: u32 = PDSHIFT + 9;
const _PGDSHIFT: u32 = PDPSHIFT + 9;


static mut DOJOSNOOP_CR3: Option<u64> = None;
static mut DOJOSNOOP_EXEC: Option<u64> = None;
static mut DOJOSNOOP_EXIT: Option<u64> = None;

/// We use this variable to identify the length of the breakpoint instruction
/// In the current situation, it is only one byte "\xcc"
pub const BP_LEN: usize = 1;

/// According to my knowledge of AFL++, this is the default size of input
pub const FUZZ_LEN: usize = 1024;

pub const BP_BYTES: [u8; BP_LEN] = [0xcc];

const ORACLE_IP: &str = "localhost";
const ORACLE_PORT: i32 = 31337;
const ORACLE_SOCKET: &str = "/tmp/FC_SOCK";

// static mut STREAM: Option<TcpStream> = None;
static mut STREAM: Option<UnixStream> = None;


fn get_virt_indicies(addr: u64) -> (u64, u64, u64, u64) {
    let addr = addr >> PAGESHIFT;
    let pt = (addr >> (0 * 9)) & 0x1ff; 
    let pd = (addr >> (1 * 9)) & 0x1ff; 
    let pdp = (addr >> (2 * 9)) & 0x1ff;
    let pgd = (addr >> (3 * 9)) & 0x1ff;
    (pgd, pdp, pd, pt)
}

/// Convert a virtual address into physical
pub fn pagewalk(gm: GuestMemoryMmap, addr: u64, cr3: u64) -> u64 {
    let indicies = get_virt_indicies(addr);
    let (pgd_idx, pdp_idx, pd_idx, pt_idx) = indicies;

    // let pgd_data = read_page(cr3);
    // let phys_pgd_data = &pgd_data[pgd_idx * 8..(pgd_idx + 1) * 8];
    let phys_pgd_data = &mut [0u8; 8];
    // log_jaeger_warning("pagewalk", format!("Reading :{:#016x}", cr3 + pgd_idx * 8).as_str());
    gm.read_slice(phys_pgd_data, GuestAddress((cr3 & !(0xfff)) + pgd_idx * 8))
    .expect("Failed to read cr3");
    let phys_pgd_entry = u64::from_le_bytes(*phys_pgd_data);
    let phys_pdp_address = phys_pgd_entry & !(0xfff) & !(1 << 63);
    if phys_pgd_entry == 0 {
        log_jaeger_warning("pagewalk", "phys_pgd_entry is 0");
        return 0; 
    }

    // let pdp_data = read_page(phys_pdp_address);
    // let phys_pdp_data = &pdp_data[pdp_idx * 8..(pdp_idx + 1) * 8];
    let phys_pdp_data = &mut [0u8; 8];
    // log_jaeger_warning("pagewalk", format!("Reading :{:#016x}", phys_pdp_address + pdp_idx * 8).as_str());
    gm.read_slice(phys_pdp_data, GuestAddress(phys_pdp_address + pdp_idx * 8))
    .expect("Failed to read phys_pdp_address");
    let phys_pdp_entry = u64::from_le_bytes(*phys_pdp_data);
    let phys_pd_address = phys_pdp_entry & !(0xfff) & !(1 << 63);
    if phys_pdp_entry == 0 {
        log_jaeger_warning("pagewalk", "phys_pdp_entry is 0");
        return 0;
    }
    if (phys_pdp_entry >> 7) & 1 == 1 {
        return (phys_pd_address + (addr & ((1 << PDPSHIFT) - 1))) as u64; 
    }

    // let pd_data = read_page(phys_pd_address);
    // let phys_pd_data = &pd_data[pd_idx * 8..(pd_idx + 1) * 8];
    let phys_pd_data = &mut [0u8; 8];
    // log_jaeger_warning("pagewalk", format!("Reading :{:#016x}", phys_pd_address + pd_idx * 8).as_str());
    gm.read_slice(phys_pd_data, GuestAddress(phys_pd_address + pd_idx * 8))
    .expect("Failed to read phys_pd_address");
    let phys_pd_entry = u64::from_le_bytes(*phys_pd_data);
    let phys_pt_address = phys_pd_entry & !(0xfff) & !(1 << 63);
    if phys_pd_entry == 0 {
        log_jaeger_warning("pagewalk", "phys_pd_entry is 0");
        return 0;
    }
    if (phys_pd_entry >> 7) & 1 == 1 { 
        return (phys_pt_address + (addr & ((1 << PDSHIFT) - 1))) as u64;
    }

    // let pt_data = read_page(phys_pt_address);
    // let phys_pt_data = &pt_data[pt_idx * 8..(pt_idx + 1) * 8];
    let phys_pt_data = &mut [0u8; 8];
    // log_jaeger_warning("pagewalk", format!("Reading :{:#016x}", phys_pt_address + pt_idx * 8).as_str());
    gm.read_slice(phys_pt_data, GuestAddress(phys_pt_address + pt_idx * 8))
    .expect("Failed to read phys_pt_address");
    let phys_pt_entry = u64::from_le_bytes(*phys_pt_data);
    let phys_address = phys_pt_entry & !(0xfff) & !(1 << 63);
    if phys_pt_entry == 0 {
        log_jaeger_warning("pagewalk", "phys_pt_entry is 0");
        return 0;
    }
    return (phys_address + (addr & ((1 << PTSHIFT) - 1))) as u64;
}


/// Wrapper for sending messages to Oracle
fn send_message(msg: &str) -> std::io::Result<()> {
    unsafe {
        let mut stream = STREAM.as_ref().unwrap();
        match stream.write(msg.as_bytes()) {
            Ok(_) => Ok(()),
            Err(e) => {
                println!("Could not send message: {}", e);
                Err(e)
            }
        }
    }
}

/*
/// Wrapper for receiving messages from Oracle
fn recv_message(size: usize) -> std::io::Result<Vec<u8>> {
    unsafe {
        let mut stream = STREAM.as_ref().unwrap();
        let mut msg: Vec<u8> = vec![0; size as usize]; 
        match stream.read_exact(&mut msg) {
            Ok(_) => Ok(msg),
            Err(e) => {
                println!("Error reading from server: {}", e);
                Err(e)
            }
        }
    }
}
*/

// Wrapper for receiving one byte from Oracle
fn recv_byte() -> std::io::Result<u8> {
    unsafe {
        let mut stream = STREAM.as_ref().unwrap();
        let mut msg: [u8; 1] = [0];     
        match stream.read_exact(&mut msg) {
            Ok(_) => Ok(msg[0]),            
            Err(e) => {
                println!("Error reading from server: {}", e);
                Err(e)
            }
        }
    }
}


/// Wrapper for reading one line from Oracle
fn recvline() -> std::io::Result<String> {
    log_jaeger_warning("recvline", "Reading line");
    let mut data: Vec<u8> = Vec::new(); 
    loop {
        match recv_byte() {
            Ok(byte) => {
                match byte == 10 {              
                    true => break,                  
                    false => data.push(byte)        
                };
            },
            Err(e) => {
                println!("Error reading from server: {}", e);
            }
        };
    };
    let s = String::from_utf8(data).expect("Found invalid UTF-8");
    // println!("Received line: {:?}", s);
    log_jaeger_warning("recvline", "Finished");
    Ok(s)
}


/// This function will be called by the `running` function in Vcpu
/// This function is supposed to set up the connection with Oracle
pub fn init_handshake() -> std::io::Result<()> {
    unsafe { 
        match UnixStream::connect(ORACLE_SOCKET) {
            Ok(stream) => {
                STREAM = Some(stream);
                let _flag = get_init();
                Ok(())
            }
            Err(e) => {
                println!("Could not connect to oracle server: {}", e);
                STREAM = None;
                Err(e)
            }
        }
        // match TcpStream::connect(format!("{}:{}", ORACLE_IP, ORACLE_PORT)) {
        //     Ok(stream) => {
        //         STREAM = Some(stream);
        //         let _flag = get_init();
        //         Ok(())
        //     }
        //     Err(e) => {
        //         println!("Could not connect to oracle server: {}", e);
        //         STREAM = None;
        //         Err(e)
        //     }
        // }
    }
}


/// This function is used to inform the Oracle of a breakpoint event
/// Oracle will let us know if this is the entrypoint
pub fn notify_oracle(pc_addr:u64, phys_addr: u64, cr3: u64) -> (bool, bool, bool) {
    let msg = format!("{:#016x}:{:#016x}:{:#016x}\n", pc_addr, phys_addr, cr3);
    match send_message(&msg) {
        Ok(()) => println!("Sent breakpoint addr: {:#016x}", pc_addr),
        Err(e) => panic!("{}", e)
    };
    let is_first: bool =  match recvline() {
        Ok(data) => data.trim().parse::<bool>().unwrap(),
        Err(e) => {
            println!("Could not decode: {}", e);
            false
        }
    };
    let take_snapshot: bool =  match recvline() {
        Ok(data) => data.trim().parse::<bool>().unwrap(),
        Err(e) => {
            println!("Could not decode: {}", e);
            false
        }
    };
    let fuzz: bool =  match recvline() {
        Ok(data) => data.trim().parse::<bool>().unwrap(),
        Err(e) => {
            println!("Could not decode: {}", e);
            false
        }
    };
    (is_first, take_snapshot, fuzz)
}


pub fn notify_exec(prog_path: &str) {
    let msg = format!("EXEC:{}\n", prog_path);
    match send_message(&msg) {
        Ok(()) => println!("Sent exec path: {}", prog_path),
        Err(e) => panic!("{}", e)
    };
}


pub fn notify_exit(prog_path: &str, exit_code: u64) -> u64 {
    log_jaeger_warning("notify_exit", "Notifying");
    let msg = format!("EXIT:{}={}\n", prog_path, exit_code);
    match send_message(&msg) {
        Ok(()) => println!("Sent exit code: {}", exit_code),
        Err(e) => panic!("{}", e)
    };
    let mut ret:u64 = HANDLED;
    log_jaeger_warning("notify_exit", "reading line");
    match recvline() {
        Ok(data) => {ret = data.parse::<u64>().unwrap()},
        Err(e) => {
            println!("Could not decode: {}", e);
        }
    };
    log_jaeger_warning("notify_exit", "Finished");
    ret
}


/// The Oracle will send us the physical addresses for the program
pub fn get_offsets() -> Vec<u64> {
    log_jaeger_warning("get_offsets", "Getting REQ");
    let msg = format!("REQ\n");
    match send_message(&msg) {
        Ok(()) => println!("Sent message: REQ"),
        Err(e) => panic!("{}", e)
    };
    log_jaeger_warning("get_offsets", "Getting values");
    let mut values: Vec<u64> = Vec::new();
    loop {
        log_jaeger_warning("get_offsets", "loop getting values");
        match recvline() {
            Ok(data) => {
                match data.parse::<u64>() {
                    Ok(x) => values.push(x),
                    Err(_e) => break,
                }
            },
            Err(e) => {
                println!("Could not decode: {}", e);
                break;
            }
        };
    }
    // println!("Received values: {:?}", values);
    log_jaeger_warning("get_offsets", "Finished");
    values
}

/// The address of the current RIP and the physical address will be sent to the Oracle
/// The Oracle will send us the bytes that should be replaced
pub fn get_bytes() -> [u8; BP_LEN] {
    log_jaeger_warning("get_bytes", "Getting BYTES");
    let msg = format!("BYTES\n");
    match send_message(&msg) {
        Ok(()) => println!("Sent message: BYTES"),
        Err(e) => panic!("{}", e)
    };
    let mut values: [u8; BP_LEN] = [0; BP_LEN];
    for i in 0..BP_LEN {
        match recvline() {
            Ok(data) => {
                match data.parse::<u8>() {
                    Ok(x) => {values[i] = x},
                    Err(_e) => break
                }
            },
            Err(e) => println!("Could not decode: {}", e)
        };
    }
    // println!("Received values: {:?}", values);
    log_jaeger_warning("get_bytes", "Finished");
    values
}


/// Here, we request the fuzzing input from the Oracle
pub fn get_fuzz_bytes() -> ([u8; FUZZ_LEN], usize) {
    let msg = format!("BYTES\n");
    match send_message(&msg) {
        Ok(()) => println!("Sent message: BYTES"),
        Err(e) => panic!("{}", e)
    };
    let mut values: [u8; FUZZ_LEN] = [0; FUZZ_LEN];
    let mut sz: usize = 0;
    for i in 0..FUZZ_LEN {
        match recvline() {
            Ok(data) => {
                match data.parse::<u8>() {
                    Ok(x) => {
                        values[i] = x;
                        sz += 1;
                    },
                    Err(_e) => break
                }
            },
            Err(e) => println!("Could not decode: {}", e)
        };
    }
    // println!("Received values: {:?}", values);
    (values, sz)
}


/// We will try to request the DOJOSNOOP variables from the oracle
/// Returns true if we got all three variables
/// false otherwise
pub fn get_init() -> bool {
    let id: u32 = process::id();
    let msg = format!("INIT:0x0:0x0:0x0:{}\n", id);
    match send_message(&msg) {
        Ok(()) => println!("Sent message: INIT"),
        Err(e) => panic!("{}", e)
    };
    let mut values: [u64; 3] = [0; 3];
    for i in 0..3 {
        match recvline() {
            Ok(data) => values[i] = data.parse::<u64>().unwrap(),
            Err(e) => println!("Could not decode: {}", e)
        };
    }
    // println!("Received values: {:?}", values);
    let mut flag: bool = true;
    for i in values {
        if i == 0 {
            flag = false;
            break;
        }
    }
    if flag == true {
        // println!("Updating dojosnoop variables");
        unsafe {
            DOJOSNOOP_CR3 = Some(values[0]);
            DOJOSNOOP_EXEC = Some(values[1]);
            DOJOSNOOP_EXIT = Some(values[2]);
        }
        // log_jaeger_warning("get_init", format!("[INIT] CR3 = {:#016x}\tEXEC = {:#016x}\tEXIT = {:#016x}",
        // values[0], values[1], values[2]).as_str());
    }
    flag
}


/// Send the DOJOSNOOP variables to oracle
fn send_init() {
    log_jaeger_warning("send_init", "Sending DOJOSNOOP to oracle");
    let pid: u32 = process::id();
    let msg = unsafe {
        format!("INIT:{:#016x}:{:#016x}:{:#016x}:{}\n",
            DOJOSNOOP_CR3.clone().unwrap(),
            DOJOSNOOP_EXEC.clone().unwrap(),
            DOJOSNOOP_EXIT.clone().unwrap(),
            pid
        )
    };
    match send_message(&msg) {
        Ok(()) => println!("Sent message: INIT"),
        Err(e) => panic!("{}", e)
    };
    let mut values: [u64; 3] = [0; 3];
    for i in 0..3 {
        match recvline() {
            Ok(data) => values[i] = {
                data.parse::<u64>().unwrap()
            },
            Err(e) => println!("Could not decode: {}", e)
        };
    }
    // println!("Received values: {:?}", values);
}


pub fn handle_kvm_exit_debug(rip: u64, phys_addr: u64, cr3: u64) -> u64 {
    unsafe {
        if DOJOSNOOP_CR3.is_none() {
            assert!(DOJOSNOOP_EXEC.is_none(), "dojosnoop_exec isn't None");
            DOJOSNOOP_CR3 = Some(cr3);
            DOJOSNOOP_EXEC = Some(rip);
            log_jaeger_warning("handle_kvm_exit_debug", format!("[INIT] CR3 = {:#016x}\tEXEC = {:#016x}", cr3, rip).as_str());
            return INIT;
        } else if DOJOSNOOP_EXIT.is_none() {
            log_jaeger_warning("handle_kvm_exit_debug", format!("[INIT] EXIT = {:#016x}", rip).as_str());
            DOJOSNOOP_EXIT = Some(rip);
            send_init();
            return INIT_COMPLETE;
        } else if DOJOSNOOP_CR3 == Some(cr3) {
            if DOJOSNOOP_EXEC == Some(rip) {
                log_jaeger_warning("handle_kvm_exit_debug", format!("EXEC = {:#016x}", rip).as_str());
                return EXEC;
            } else if DOJOSNOOP_EXIT == Some(rip) {
                log_jaeger_warning("handle_kvm_exit_debug", format!("EXIT = {:#016x}", rip).as_str());
                return EXIT;
            }
        }
    }

    // We've already initialized all the required variables.
    // Handle this situation properly now
    let (is_first, take_snapshot, fuzz) = notify_oracle(rip, phys_addr, cr3);
    if take_snapshot == true {
        return SNAPSHOT;
    }
    if fuzz == true {
        return FUZZ;
    }
    if is_first == true {
        // If we get here, it means that we've hit the breakpoint injected into
        // the entry point of the current program.
        // Tell FC that we need to modify the program
        log_jaeger_warning("handle_kvm_exit_debug", format!("MODIFY = {:#016x}", rip).as_str());
        return MODIFY;
    } else {
        // If we get here, it means that we've hit an injected breakpoint
        // Tell FC that we need to unmodify
        log_jaeger_warning("handle_kvm_exit_debug", format!("UNMODIFY = {:#016x}", rip).as_str());
        return UNMODIFY;
    }
}
