#!/bin/bash

python3 ../../shellcode.py target/x86_64-pc-windows-gnu/release/reverse_tcp_tdi.dll | grep -v '/tmp/' > /tmp/hexwut

gedit /tmp/hexwut
