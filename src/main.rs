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

fn main() {
    // println!("Hello, world!");
    let engine = keystone::Keystone::new(keystone::Arch::X86, 
                                         keystone::MODE_LITTLE_ENDIAN | keystone::MODE_32)
        .expect("could not initialize Keystone engine");
    engine.option(keystone::OptionType::SYNTAX, keystone::OPT_SYNTAX_NASM)
        .expect("could not set option to nasm syntax");

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
        .get_matches();

    let base_address = if matches.is_present(ARGUMENT_BASE) {
        value_t!(matches, ARGUMENT_BASE, u64).unwrap_or(0x0)
    }
    else {
        0x0
    };

    let asm_code = matches.value_of(ARGUMENT_ASM).unwrap(); // should not panic
    let asm_code: Vec<_> = asm_code.split(';').collect();
    let asm_code: Vec<_> = asm_code.into_iter().map(|ins| ins.trim()).collect();

    let mut asm_results: Vec<_> = Vec::new();
    let mut ins_base_address = base_address;
    for ins in asm_code {
        if let Ok(asm_result) = engine.asm(ins.to_string(), ins_base_address) {
            let opcode_len = asm_result.bytes.len();
            let opcode_strs: Vec<_> = asm_result.bytes
                .into_iter()
                .map(|opc| format!("{:02x}", opc) )
                .collect();
            let opcode_string = opcode_strs.join(" ");
            let asm_result = format!("0x{:016x}\t{}\t{}", ins_base_address, &opcode_string, ins);
            asm_results.push(asm_result);

            ins_base_address += opcode_len as u64;
        }
        else {
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
