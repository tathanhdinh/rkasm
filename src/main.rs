extern crate keystone;
#[macro_use]
extern crate clap;
extern crate tabwriter;

use std::io::Write;

static APPLICATION_NAME: &'static str = "rkasm";
static APPLICATION_VERSION: &'static str = "0.1.0";
static APPLICATION_AUTHOR: &'static str = "TA Thanh Dinh <tathanhdinh@gmail.com>";
static APPLICATION_ABOUT: &'static str = "A x86 assembler";

static ARGUMENT_ASM: &'static str = "x86 assembly";
static ARGUMENT_BASE: &'static str = "base address";
static ARGUMENT_MODE: &'static str = "assembling mode";

fn main() {
    // println!("Hello, world!");
    let matches = clap::App::new(APPLICATION_NAME)
        .version(APPLICATION_VERSION)
        .author(APPLICATION_AUTHOR)
        .about(APPLICATION_ABOUT)
        .arg(clap::Arg::with_name(ARGUMENT_ASM)
             .required(true)
             .index(1))
        .arg(clap::Arg::with_name(ARGUMENT_BASE)
             .short("b")
             .long("base")
             .takes_value(true)
             .default_value("0"))
        .arg(clap::Arg::with_name(ARGUMENT_MODE)
             .short("m")
             .long("mode")
             .takes_value(true)
             .default_value("x64"))
        .get_matches();

    let asm_mode = if matches.is_present(ARGUMENT_MODE) {
        match matches.value_of(ARGUMENT_MODE).unwrap() {
            "x32" => {
                keystone::MODE_32
            },
            "x64" => {
                keystone::MODE_64
            },
            _ => {
                // keystone::MODE_64
                println!("{}", "bad assembling mode (should be either x32 or x64)");
                return;
            }
        }
    }
    else {
        keystone::MODE_64
    };

    let base_address = if matches.is_present(ARGUMENT_BASE) {
        value_t!(matches, ARGUMENT_BASE, u64).unwrap_or(0x0)
    }
    else {
        0x0
    };

    let engine = keystone::Keystone::new(keystone::Arch::X86, 
                                         keystone::MODE_LITTLE_ENDIAN | asm_mode)
        .expect("could not initialize Keystone engine");
    engine.option(keystone::OptionType::SYNTAX, keystone::OPT_SYNTAX_NASM)
        .expect("could not set option to nasm syntax");

    let asm_code = matches.value_of(ARGUMENT_ASM).unwrap(); // should not panic since required
    let asm_code: Vec<_> = asm_code.split(';').collect();
    let asm_code: Vec<_> = asm_code.into_iter().map(|ins| ins.trim()).collect();

    let mut asm_results: Vec<_> = Vec::new();
    let mut asm_result;
    let mut ins_base_address = base_address;
    for ins in asm_code {
        let assembling_result = 
            if let Ok(result) = engine.asm(ins.to_string(), ins_base_address) {
                let opcode_len = result.bytes.len();
                let opcode_strs: Vec<_> = result.bytes
                    .into_iter()
                    .map(|opc| format!("{:02x}", opc))
                    .collect();
                let opcode_string = opcode_strs.join(" ");
                
                asm_result = format!("0x{:x}\t{}\t{}", ins_base_address, &opcode_string, ins);
                // asm_results.push(asm_result);
                // Ok(format!("0x{:016x}\t{}\t{}", ins_base_address, &opcode_string, ins))
                ins_base_address += opcode_len as u64;
                Ok(())
            }
            else {
                asm_result = format!("0x{:x}\t{}\t{}", ins_base_address, "error", ins);
                // asm_results.push(asm_result);
                // break;
                // Err(format!("0x{:016x}\t{}\t{}", ins_base_address, "error", ins))
                Err(())
            };

        asm_results.push(asm_result);
        if assembling_result.is_err() {
            break;
        }
    }
    let asm_results = asm_results.join("\r\n");
    // println!("{}", asm_results.len());

    // let mut tw = tabwriter::TabWriter::new(Vec::new()).padding(2);
    let mut tw = tabwriter::TabWriter::new(std::io::stdout()).padding(4);
    // tw.w
    // write!(&mut tw, &asm_results);
    writeln!(&mut tw, "{}", asm_results).unwrap();
    tw.flush().unwrap();

    // if let Ok(asm_result) = engine.asm(asm_code.to_string(), base_address) {
    //     // println!("{}", asm_result);
    //     for byte in asm_result.bytes {
    //         print!("{:02x} ", byte);
    //     }
    //     println!("");
    // }
    // else {
    //     println!("{}", "could not assemble")
    // }

}
