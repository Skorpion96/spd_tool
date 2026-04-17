# spd_tool
A simple GUI for spd_dump
There isn't much to say, an image will be a better explanation of a lot of words. What i can say is that the tool is untested, i only tested the fdls mechanic and full flash, sigle/multiple partitions flash but without connecting a real device, as i don't have one to flash for now. The tool might need fixing and in case i can do that later. The spd_dump used is:https://github.com/TomKing062/spreadtrum_flash, the tool is written in C and uses FLTK for the GUI. I used claude and chatgpt to develop it. To build first install libfltk1.3-dev and build-essential, then compile it with: g++ spd_flash.cpp -o spd_flash -lfltk

<img width="860" height="652" alt="gui" src="https://github.com/user-attachments/assets/66e51120-f63c-48e5-9955-d6f666fe7f39" />
