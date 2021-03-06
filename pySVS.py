#!/usr/bin/python3 

from binascii import hexlify
from tkinter import * 
from tkinter import ttk
from PIL import ImageTk, Image
import time
import traceback
from threading import *
import requests
import sys
import asyncio
import platform
from bleak import BleakClient


#EDIT THIS VALUE#####################
SVS_MAC_ADDRESS = "12:34:56:78:9A:BC"
#####################################

################    SB-1000-PRO CONFIG    #########################################
STEP = 2560

SERV01 = "0000fef6-0000-1000-8000-00805f9b34fb"
CHAR01 = "005f0005-2ff2-4ed5-b045-4c7463617865"
CHAR02 = "005f0004-2ff2-4ed5-b045-4c7463617865"
CHAR03 = "005f0003-2ff2-4ed5-b045-4c7463617865"
CHAR04 = "005f0002-2ff2-4ed5-b045-4c7463617865"

SERV02 = "1fee6acf-a826-4e37-9635-4d8a01642c5d"
CHAR11 = "7691b78a-9015-4367-9b95-fc631c412cc6"  #change device name
CHAR12 = "6409d79d-cd28-479c-a639-92f9e1948b43"  #notification handle 0x12

SERV03 = "0000180a-0000-1000-8000-00805f9b34fb"
CHAR21 = "00002a29-0000-1000-8000-00805f9b34fb"
CHAR22 = "00002a25-0000-1000-8000-00805f9b34fb"

SERV04 = "00001801-0000-1000-8000-00805f9b34fb"
CHAR31 = "00002a05-0000-1000-8000-00805f9b34fb"

CHARACTERISTIC_UUID = CHAR12

SVS_COMMANDS = 	{
		"SET": b'\xaa\xf0\x1f\x11\x00', 
		"ASK": b'\xaa\xf1\x1f\x0f\x00'
		}
SVS_PARAMS = 	{
		"VOLUME": {"bin":b'\x04\x00\x00\x00\x2c\x00\x02', "limits": [-60,0], "limits_type":0, "reference": 0x1000000},
		"PHASE": {"bin":b'\x04\x00\x00\x00\x2e\x00\x02', "limits": [0,180], "limits_type":0, "reference": 0},
		"LOW_PASS_FILTER_ALL_SETTINGS":{"bin":b'\x04\x00\x00\x00\x08\x00\x06', "limits": ("LFE", "LOW_PASS_FILTER_FREQ","LOW_PASS_FILTER_SLOPE"), "limits_type":"combined", "reference": 0},
		"LFE":{"bin":b'\x04\x00\x00\x00\x08\x00\x02', "limits": [0,1], "limits_type":1, "reference": 0}, #[ON, OFF], discrete type
		"LOW_PASS_FILTER_FREQ":{"bin":b'\x04\x00\x00\x00\x0a\x00\x02', "limits": [30, 200], "limits_type":0, "reference": 0},
		"LOW_PASS_FILTER_SLOPE":{"bin":b'\x04\x00\x00\x00\x0c\x00\x02',"limits": [6, 12, 18, 24], "limits_type":1, "reference": 0}, #discrete type
		"ROOM_GAIN_ALL_SETTINGS":{"bin":b'\x04\x00\x00\x00\x26\x00\x06', "limits": ("ROOM_GAIN_ENABLE", "ROOM_GAIN_FREQ","ROOM_GAIN_SLOPE"), "limits_type":"combined", "reference": 0},
		"ROOM_GAIN_ENABLE":{"bin":b'\x04\x00\x00\x00\x26\x00\x02', "limits": [1,0], "limits_type":1, "reference": 0}, #[ON, OFF], discrete type
		"ROOM_GAIN_FREQ":{"bin":b'\x04\x00\x00\x00\x28\x00\x02', "limits": [25, 31, 40], "limits_type":1, "reference": 0}, #discrete type
		"ROOM_GAIN_SLOPE":{"bin":b'\x04\x00\x00\x00\x2a\x00\x02', "limits": [6,12], "limits_type":1, "reference": 0}, #discrete type
        "POWER_SETTING":{"bin":b'\x04\x00\x00\x00\x04\x00\x02', "limits": [0,2], "limits_type":0, "reference": 0}
		}
##############   End SB-1000-PRO CONFIG    #############################

##############    Bleak Routines    ######################
ADDRESS = (
    SVS_MAC_ADDRESS
    if platform.system() != "Darwin"
    else "B9EA5233-37EF-4DD6-87A8-2A875E821C46"
)

PARTIAL_FRAME=b''
crc_error = False
def notification_handler(handle, data):
    #Everything that the svs subwoofer sends to us comes to this callback
    global PARTIAL_FRAME
    global crc_error
    if data[0] == 0xAA:
    #detected a frame start. Start building frame
        if crc_error == True:
        #crc_error was not reset before, print crc error and show PREVIOUS wrong frame
            print("Data with CRC missmatch received: " + hexlify(PARTIAL_FRAME))
        PARTIAL_FRAME = data
    else:
    #detected a frame fragment. Add it to the previous partial frame
        PARTIAL_FRAME = PARTIAL_FRAME + data

    if checksum_calc(PARTIAL_FRAME[:len(PARTIAL_FRAME)-2]) == PARTIAL_FRAME[len(PARTIAL_FRAME)-2:]:
        crc_error = False
        FULL_FRAME = PARTIAL_FRAME
        if SVS_PARAMS["VOLUME"]["bin"] in FULL_FRAME:
            print("<- Received VOLUME data (Handle %s):  %s" % (hex(handle), hexlify(FULL_FRAME)))
            vol_slider.set(hex2data(FULL_FRAME)[0])
        elif SVS_PARAMS["PHASE"]["bin"] in FULL_FRAME:
            print("<- Received PHASE data (Handle %s):  %s" % (hex(handle), hexlify(FULL_FRAME)))
            phase_slider.set(hex2data(FULL_FRAME)[0])
        elif SVS_PARAMS["LFE"]["bin"] in FULL_FRAME:
            print("<- Received LFE ON/OFF data (Handle %s):  %s" % (hex(handle), hexlify(FULL_FRAME)))
            lfe_var.set(not(bool((hex2data(FULL_FRAME)[0]))))
            refresh_conditional_widgets()
        elif SVS_PARAMS["LOW_PASS_FILTER_FREQ"]["bin"] in FULL_FRAME:
            print("<- Received LOW PASS FILTER FREQUENCY data (Handle %s):  %s" % (hex(handle), hexlify(FULL_FRAME)))
            lpfilter_slider.set(hex2data(FULL_FRAME)[0])
        elif SVS_PARAMS["LOW_PASS_FILTER_SLOPE"]["bin"] in FULL_FRAME:
            print("<- Received LOW PASS FILTER SLOPE data (Handle %s):  %s" % (hex(handle), hexlify(FULL_FRAME)))
            lpfilter_slope_combo.current(SVS_PARAMS["LOW_PASS_FILTER_SLOPE"]["limits"].index(hex2data(FULL_FRAME)[0]))
        elif SVS_PARAMS["LOW_PASS_FILTER_ALL_SETTINGS"]["bin"] in FULL_FRAME:
            print("<- Received LOW PASS FILTER FULL_SETTINGS data (Handle %s):  %s" % (hex(handle), hexlify(FULL_FRAME)))
            values = hex2data(FULL_FRAME)
            lfe_var.set(not(bool(values[0])))
            lpfilter_slider.set(values[1])
            lpfilter_slope_combo.current(SVS_PARAMS["LOW_PASS_FILTER_SLOPE"]["limits"].index(hex2data(FULL_FRAME)[2]))
            refresh_conditional_widgets()
        elif SVS_PARAMS["ROOM_GAIN_ENABLE"]["bin"] in FULL_FRAME:
            print("<- Received ROOM GAIN ON/OFF data (Handle %s):  %s" % (hex(handle), hexlify(FULL_FRAME)))
            room_gain_var.set(bool(hex2data(FULL_FRAME)[0]))
            refresh_conditional_widgets()
        elif SVS_PARAMS["ROOM_GAIN_FREQ"]["bin"] in FULL_FRAME:
            print("<- Received ROOM GAIN FREQUENCY data (Handle %s):  %s" % (hex(handle), hexlify(FULL_FRAME)))
            room_gain_slider.set(hex2data(FULL_FRAME)[0])
        elif SVS_PARAMS["ROOM_GAIN_SLOPE"]["bin"] in FULL_FRAME:
            print("<- Received ROOM GAIN SLOPE data (Handle %s):  %s" % (hex(handle), hexlify(FULL_FRAME)))
            room_gain_slope_combo.current(SVS_PARAMS["ROOM_GAIN_SLOPE"]["limits"].index(hex2data(FULL_FRAME)[0]))
        elif SVS_PARAMS["ROOM_GAIN_ALL_SETTINGS"]["bin"] in FULL_FRAME:
            print("<- Received ROOM GAIN FULL SETTINGS data (Handle %s):  %s" % (hex(handle), hexlify(FULL_FRAME)))
            values = hex2data(FULL_FRAME)
            room_gain_var.set(bool(values[0]))
            room_gain_slider.set(values[1])
            room_gain_slope_combo.current(SVS_PARAMS["ROOM_GAIN_SLOPE"]["limits"].index(hex2data(FULL_FRAME)[2]))
            refresh_conditional_widgets()
        elif SVS_PARAMS["POWER_SETTING"]["bin"] in FULL_FRAME:
            print("<- Received POWER SETTING data (Handle %s):  %s" % (hex(handle), hexlify(FULL_FRAME)))
        else:
            print("<- Received unknown data (Handle %s): %s" % (hex(handle), hexlify(FULL_FRAME)))
    else:
        crc_error = True

def threading():
    # Call function
    t1=Thread(target=bleak_device)
    t1.start()

def bleak_device():
    asyncio.run(
        gatt_thread(
            sys.argv[1] if len(sys.argv) > 1 else ADDRESS,
            sys.argv[2] if len(sys.argv) > 2 else CHARACTERISTIC_UUID,
        )
    )

RUN_THREAD = True
async def gatt_thread(address, char_uuid):
    async with BleakClient(address) as client:
        print(f"Connected: {client.is_connected}")

        #print services
        svcs = await client.get_services()
        for service in svcs:
            print("SERVICE: " + str(service))
            for char in service.characteristics:
                print("\tCHARACTERISTIC: " + str(char))
            print("")
        #subscribe to svs parameters characteristic
        await client.start_notify(char_uuid, notification_handler)

        #ask subwoofer for config
        await client.write_gatt_char(char_uuid, svs("ASK", "VOLUME"))
        await asyncio.sleep(0.1)
        await client.write_gatt_char(char_uuid, svs("ASK", "PHASE"))
        await asyncio.sleep(0.1)
        await client.write_gatt_char(char_uuid, svs("ASK", "LOW_PASS_FILTER_ALL_SETTINGS"))
        await asyncio.sleep(0.1)
        await client.write_gatt_char(char_uuid, svs("ASK", "ROOM_GAIN_ALL_SETTINGS"))
        await asyncio.sleep(0.1)

        while RUN_THREAD:
        #don't let this method die in order to RX continuosly
             if len(TX.BUFFER) > 0: 
                 await client.write_gatt_char(char_uuid, TX.BUFFER)
                 TX.BUFFER = ""
             await asyncio.sleep(0.2)
        print("Bleak Client Thread closed")

def svs(command, param, data=b'\x00'):
   frame = SVS_COMMANDS[command] + SVS_PARAMS[param]["bin"] + data
   frame = frame + checksum_calc(frame)
   print("-> " + command + " " + param + " " + str(hexlify(data)))
   return frame

class TX:
    BUFFER = ""
    
##############   End Bleak Routines    ######################

##############    CRC16 XMODEM Routines    ######################
def checksum_calc(in_data):
    checksum = crcb(*[ int(in_data.hex()[i:i+2], 16) for i in range(0, len(in_data.hex()), 2)])
    checksum = checksum.to_bytes(2, 'little')
    return checksum

def _initial(c):
    crc = 0
    c = c << 8
    for j in range(8):
        if (crc ^ c) & 0x8000:
            crc = (crc << 1) ^ 0x1021
        else:
            crc = crc << 1
        c = c << 1
    return crc

_tab = [ _initial(i) for i in range(256) ]

def _update_crc(crc, c):
    cc = 0xff & c

    tmp = (crc >> 8) ^ cc
    crc = (crc << 8) ^ _tab[tmp & 0xff]
    crc = crc & 0xffff
    return crc

def crcb(*i):
    crc = 0
    for c in i:
        crc = _update_crc(crc, c)
    return crc
########### End CRC16 XMODEM Routines #################

###############   GUI Routines   ######################

def update_vol(self):
    TX.BUFFER = svs("SET","VOLUME",data2hex(vol_slider.get(), SVS_PARAMS["VOLUME"]["reference"]))

def update_phase(self):
    TX.BUFFER = svs("SET","PHASE",data2hex(phase_slider.get()))

def lfe_opt_changed():
    refresh_conditional_widgets()
    TX.BUFFER = svs("SET","LFE",data2hex(not(lfe_var.get())))

def update_lpfilter_freq(self):
    if not lfe_var.get():
    #as this callback is called when the click is released, be sure only to send svs set only if lfe = off
        TX.BUFFER = svs("SET","LOW_PASS_FILTER_FREQ",data2hex(lpfilter_slider.get()))

def update_lpfilter_slope(self):
    TX.BUFFER = svs("SET","LOW_PASS_FILTER_SLOPE",data2hex(lpfilter_slope_combo.get()))

def room_gain_opt_changed():
    refresh_conditional_widgets()
    TX.BUFFER = svs("SET","ROOM_GAIN_ENABLE", data2hex(room_gain_var.get()))

def update_room_gain_freq(self):
    if room_gain_var.get():
    #as this callback is called when the click is released, be sure only to send svs set only if room_gain = on
        TX.BUFFER = svs("SET","ROOM_GAIN_FREQ", data2hex(room_gain_slider.get()))

def update_room_gain_slope(self):
    TX.BUFFER = svs("SET","ROOM_GAIN_SLOPE", data2hex(room_gain_slope_combo.get()))

def make_discrete_slider(value):
    new_value = min(SVS_PARAMS["ROOM_GAIN_FREQ"]["limits"], key=lambda x:abs(x-float(value)))
    room_gain_slider.set(new_value)

def refresh_conditional_widgets():
    #refresh state of widgets that depend on other widgets values
    if lfe_var.get():
        lpfilter_slider.configure(state='disabled')
        lpfilter_slope_combo.configure(state='disabled')
        lfe_checkbox.configure(text='LFE ON')
    else:
        lpfilter_slider.configure(state='normal')
        lpfilter_slope_combo.configure(state='readonly')
        lfe_checkbox.configure(text='LFE OFF')

    if room_gain_var.get():
        room_gain_slider.configure(state='normal')
        room_gain_slope_combo.configure(state='readonly')
        room_gain_checkbox.configure(text='Room Gain Compensation ON')
    else:
        room_gain_slider.configure(state='disabled')
        room_gain_slope_combo.configure(state='disabled')
        room_gain_checkbox.configure(text='Room Gain Compensation OFF')

def on_closing():
    print("Exiting...")
    global RUN_THREAD
    RUN_THREAD = False
    window.destroy()
    quit()
###########   End GUI Routines   ###################

###########   AUX Routines   ###################
def data2hex(level, reference=0):
    value_hex = (STEP*int(level) + reference).to_bytes(4, 'little')
    return value_hex[:3]

def hex2data(frame):
    out = []
    if len(frame) == 35:
	#multidata frame
        val_1 = 16*16*16*16*frame[18] + 16*16*frame[17] + frame[16]
        val_2 = 16*16*16*16*frame[20] + 16*16*frame[19] + frame[18]
        val_3 = 16*16*frame[21]
        values = [val_1, val_2, val_3]
    else:
	#single data frame
        values = [16*16*16*16*frame[18] + 16*16*frame[17] + frame[16]]
    for k in SVS_PARAMS.keys():
        if SVS_PARAMS[k]["bin"] in frame:
            frame_type = k
            break;
    for val in values:
        if SVS_PARAMS[frame_type]["limits_type"] == "combined":
            sub_frame_type = SVS_PARAMS[frame_type]["limits"][values.index(val)]
        else:
            sub_frame_type = frame_type
        if SVS_PARAMS[sub_frame_type]["limits_type"] == 1:
            check = SVS_PARAMS[sub_frame_type]["limits"]
        else:
            check = range(min(SVS_PARAMS[sub_frame_type]["limits"]),max(SVS_PARAMS[sub_frame_type]["limits"]) + 1)

        if int((val - SVS_PARAMS[sub_frame_type]["reference"])/STEP) in check:
            out.append(int((val - SVS_PARAMS[sub_frame_type]["reference"])/STEP))
        elif val == 0 and SVS_PARAMS[sub_frame_type]["reference"] > 0:
            out.append(max(check))
        else:
            print("Unrecognized {0} ({1}) values received".format(sub_frame_type, frame_type))
    return out

###########   End AUX Routines   ###################

###############   main()   ##########################

if __name__ == "__main__":
    try:
        window = Tk()
        window.protocol("WM_DELETE_WINDOW", on_closing)
        window.title("pySVS v.2.3 Beta - SVS Subwoofer Control")
        window.geometry('550x400')
        window.resizable(False, False)
        style= ttk.Style()
        style.map("TCombobox", fieldbackground=[("readonly", "white"),("disabled", "gray") ])
        window.columnconfigure(16, weight=1)
        window.rowconfigure(16, weight=1)

        vol_slider = Scale(window, from_=SVS_PARAMS["VOLUME"]["limits"][0], to=SVS_PARAMS["VOLUME"]["limits"][1], label = "Volume (dB)", orient=HORIZONTAL, resolution=1, length=200)
        vol_slider.grid(column=4, row=3, padx = 20, pady = 15)
        vol_slider.bind("<ButtonRelease-1>", update_vol)

        phase_slider = Scale(window, from_=SVS_PARAMS["PHASE"]["limits"][0], to=SVS_PARAMS["PHASE"]["limits"][1], label = "Phase (??)", orient=HORIZONTAL, resolution=1, length=200)
        phase_slider.grid(column=4, row=5, padx = 20, pady = 15)
        phase_slider.bind("<ButtonRelease-1>", update_phase)

        lpfilter_slider = Scale(window, from_=SVS_PARAMS["LOW_PASS_FILTER_FREQ"]["limits"][0], to=SVS_PARAMS["LOW_PASS_FILTER_FREQ"]["limits"][1], label = "Low Pass Freq. (Hz)", orient=HORIZONTAL, resolution=1, length=200)
        lpfilter_slider.grid(column=4, row=7, padx = 20, pady = 15)
        lpfilter_slider.bind("<ButtonRelease-1>", update_lpfilter_freq)
        lpfilter_slope_combo=ttk.Combobox(window,values=[str(i) + " dB" for i in SVS_PARAMS["LOW_PASS_FILTER_SLOPE"]["limits"]],width=7,state='readonly')
        lpfilter_slope_combo.grid(column=5, row=7)
        lpfilter_slope_combo.bind("<<ComboboxSelected>>", update_lpfilter_slope)
        lfe_var = BooleanVar(value=False)
        lfe_checkbox = ttk.Checkbutton(variable=lfe_var, command=lfe_opt_changed)
        lfe_checkbox.grid(sticky="W", column=6, row=7)

        room_gain_slider = Scale(window, from_=min(SVS_PARAMS["ROOM_GAIN_FREQ"]["limits"]), to=max(SVS_PARAMS["ROOM_GAIN_FREQ"]["limits"]), label = "Room Gain Freq. (Hz)", orient=HORIZONTAL, resolution=1, length=200, command=make_discrete_slider)
        room_gain_slider.bind("<ButtonRelease-1>", update_room_gain_freq)
        room_gain_slider.grid(column=4, row=9, padx = 20, pady = 15)
        room_gain_slope_combo=ttk.Combobox(window,values=[str(i) + " dB" for i in SVS_PARAMS["ROOM_GAIN_SLOPE"]["limits"]],width=7,state='readonly')
        room_gain_slope_combo.grid(column=5, row=9)
        room_gain_slope_combo.bind("<<ComboboxSelected>>", update_room_gain_slope)
        room_gain_var = BooleanVar(value=True)
        room_gain_checkbox = ttk.Checkbutton(variable = room_gain_var, command=room_gain_opt_changed)
        room_gain_checkbox.grid(sticky="W", column=6, row=9)

        try:
            subwoofer = Image.open(requests.get("https://i.imgur.com/qX85CCG.jpg", stream=True).raw)
            subwoofer = subwoofer.resize((200, 200), Image.Resampling.LANCZOS)
            subwoofer = ImageTk.PhotoImage(subwoofer)
            picframe = Label(window, image = subwoofer)
            picframe.grid(sticky="N", column=5, row=0, columnspan=9, rowspan=9)
        except:
            pass

        threading()
        window.mainloop()
	
    except Exception:
         traceback.print_exc()
