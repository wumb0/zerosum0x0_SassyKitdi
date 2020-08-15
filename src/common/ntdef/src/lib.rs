#![no_std]
#![feature(core_intrinsics)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

// types = basic types such as PVOID and UINT32
pub mod types;

// structs = structs such as UNICODE_STRING and MDL
pub mod structs;

// functions = prototype function pointers
pub mod functions;

pub mod enums;

pub mod macros;

pub mod pe;


