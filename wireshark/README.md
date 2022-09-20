# Wireshark Dissector for Zoom Media Packets

* Place zoom.lua in ~/.local/lib/wireshark/plugins.
* In Wireshark, reload plugins under *Analyze / Reload Lua Plugins*.
* Plugin automatically dissects UDP port 8801 traffic as Zoom.
* To dissect P2P traffic, right click on packet, select *"Decode As..."* and associate "ZOOM" with respective UDP port number.
