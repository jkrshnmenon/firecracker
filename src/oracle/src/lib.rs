use std::io::BufReader;
use std::io::BufRead;
use std::net::{TcpStream};
use std::io::{
    //Read, 
    Write
};

pub const INIT:u64 = 0;
pub const EXEC:u64 = 1;
pub const EXIT:u64 = 2;
pub const MODIFY:u64 = 3;
pub const UNMODIFY:u64 = 4;

pub const HANDLED:u64 = 0;
pub const STOPPED:u64 = 1;
pub const CRASHED:u64 = 2;


static mut DOJOSNOOP_CR3: Option<u64> = None;
static mut DOJOSNOOP_EXEC: Option<u64> = None;
static mut DOJOSNOOP_EXIT: Option<u64> = None;

/// We use this variable to identify the length of the breakpoint instruction
/// In the current situation, it is only one byte "\xcc"
pub const BP_LEN: usize = 1;

pub const BP_BYTES: [u8; BP_LEN] = [0xcc];

const ORACLE_IP: &str = "localhost";
const ORACLE_PORT: i32 = 31337;

static mut STREAM: Option<TcpStream> = None;

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

/// Wrapper for reading a line from Oracle
fn recvline() -> std::io::Result<String> {
    unsafe {
        let stream = STREAM.as_ref().unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        let result = reader.read_line(&mut line);
        match result {
            Ok(_) => Ok(line.trim().to_string()),
            Err(e) => {
                println!("Error reading from server: {}", e);
                Err(e)
            }
        }
    }
}


/// This function will be called by the `running` function in Vcpu
/// This function is supposed to set up the connection with Oracle
pub fn init_handshake() -> std::io::Result<()> {
    unsafe { 
        match TcpStream::connect(format!("{}:{}", ORACLE_IP, ORACLE_PORT)) {
            Ok(stream) => {
                STREAM = Some(stream);
                Ok(())
            }
            Err(e) => {
                println!("Could not connect to oracle server: {}", e);
                STREAM = None;
                Err(e)
            }
        }
    }
}


/// This function is used to inform the Oracle of a breakpoint event
/// Oracle will let us know if this is the entrypoint
pub fn notify_oracle(pc_addr:u64, phys_addr: u64) -> bool {
    let msg = format!("{:#016x}:{:#016x}\n", pc_addr, phys_addr);
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
    is_first
}


pub fn notify_exec(prog_path: &str) {
    let msg = format!("EXEC:{}\n", prog_path);
    match send_message(&msg) {
        Ok(()) => println!("Sent exec path: {}", prog_path),
        Err(e) => panic!("{}", e)
    };
}


pub fn notify_exit(prog_path: &str, exit_code: u64) -> u64 {
    let msg = format!("EXIT:{}={}\n", prog_path, exit_code);
    match send_message(&msg) {
        Ok(()) => println!("Sent exit code: {}", exit_code),
        Err(e) => panic!("{}", e)
    };
    let mut ret:u64 = HANDLED;
    match recvline() {
        Ok(data) => {ret = data.parse::<u64>().unwrap()},
        Err(e) => {
            println!("Could not decode: {}", e);
        }
    };
    ret
}


/// The Oracle will send us the physical addresses for the program
pub fn get_offsets() -> Vec<u64> {
    let msg = format!("REQ\n");
    match send_message(&msg) {
        Ok(()) => println!("Sent message: REQ"),
        Err(e) => panic!("{}", e)
    };
    let mut values: Vec<u64> = Vec::new();
    loop {
        match recvline() {
            Ok(data) => values.push(data.parse::<u64>().unwrap()),
            Err(e) => {
                println!("Could not decode: {}", e);
                break;
            }
        };
    }
    println!("Received values: {:?}", values);
    values
}

/// The address of the current RIP and the physical address will be sent to the Oracle
/// The Oracle will send us the bytes that should be replaced
pub fn get_bytes() -> [u8; BP_LEN] {
    let msg = format!("BYTES\n");
    match send_message(&msg) {
        Ok(()) => println!("Sent message: BYTES"),
        Err(e) => panic!("{}", e)
    };
    let mut values: [u8; BP_LEN] = [0; BP_LEN];
    for i in 0..BP_LEN {
        match recvline() {
            Ok(data) => values[i] = data.parse::<u8>().unwrap(),
            Err(e) => println!("Could not decode: {}", e)
        };
    }
    println!("Received values: {:?}", values);
    values
}


pub fn handle_kvm_exit_debug(rip: u64, phys_addr: u64, cr3: u64) -> u64 {
    unsafe {
        if DOJOSNOOP_CR3.is_none() {
            assert!(DOJOSNOOP_EXEC.is_none(), "dojosnoop_exec isn't None");
            DOJOSNOOP_CR3 = Some(cr3);
            DOJOSNOOP_EXEC = Some(rip);
            return INIT;
        } else if DOJOSNOOP_EXIT.is_none() {
            DOJOSNOOP_EXIT = Some(rip);
            return INIT;
        } else if DOJOSNOOP_CR3 == Some(cr3) {
            if DOJOSNOOP_EXEC == Some(rip) {
                return EXEC;
            } else if DOJOSNOOP_EXIT == Some(rip) {
                return EXIT;
            }
        }
    }

    // We've already initialized all the required variables.
    // Handle this situation properly now
    let is_first = notify_oracle(rip, phys_addr);
    if is_first == false {
        // If we get here, it means that we've hit the breakpoint injected into
        // the entry point of the current program.
        // Tell FC that we need to modify the program
        return MODIFY;
    } else {
        // If we get here, it means that we've hit an injected breakpoint
        // Tell FC that we need to unmodify
        return UNMODIFY;
    }
}
