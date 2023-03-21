use std::io::BufReader;
use std::io::BufRead;
use std::net::{TcpStream};
use std::io::{
    //Read, 
    Write
};
// use std::str::from_utf8;

/// We use this variable to identify the length of the breakpoint instruction
/// In the current situation, it is only one byte "\xcc"
pub const BP_LEN: usize = 1;

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
/// The address of the current RIP and the physical address will be sent to the Oracle
/// The Oracle will send us the bytes that should be replaced
pub fn send_breakpoint_event(pc_addr: u64, phys_addr: u64) -> (bool, [u8; BP_LEN]) {
    let msg = format!("{:#016x}:{:#016x}\n", pc_addr, phys_addr);
    match send_message(&msg) {
        Ok(()) => println!("Sent breakpoint addr: {:#016x}", pc_addr),
        Err(e) => panic!("{}", e)
    };
    let snap_time: bool =  match recvline() {
        Ok(data) => data.trim().parse::<bool>().unwrap(),
        Err(e) => {
            println!("Could not decode: {}", e);
            false
        }
    };
    let mut values: [u8; BP_LEN] = [0; BP_LEN];
    for i in 0..BP_LEN {
        match recvline() {
            Ok(data) => values[i] = data.parse::<u8>().unwrap(),
            Err(e) => println!("Could not decode: {}", e)
        };
    }
    println!("Received values: {:?}", values);
    (snap_time, values)
}