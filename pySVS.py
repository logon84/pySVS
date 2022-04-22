#!/usr/bin/python3 

from binascii import hexlify
from tkinter import * 
from tkinter import ttk
from PIL import ImageTk, Image
import time
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
VOL_LIMITS = [-60,0]
VOL_REF = 0x1000000
PHASE_LIMITS = [0, 180]
LFE_LIMITS = [0, STEP] #discrete, [ON, OFF]
LP_FREQ_LIMITS = [30, 200]
LP_SLOPE_LIMITS = [6, 12, 18, 24] #discrete values
ROOM_GAIN_LIMITS = [STEP, 0] #discrete, [ON, OFF]
ROOM_GAIN_FREQ_LIMITS = [25, 31, 40] #discrete values
ROOM_GAIN_SLOPE_LIMITS = [6, 12] #discrete values

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
		"VOLUME":b'\x04\x00\x00\x00\x2c\x00\x02', 
		"PHASE":b'\x04\x00\x00\x00\x2e\x00\x02',
		"LOW_PASS_FILTER_ALL_SETTINGS":b'\x04\x00\x00\x00\x08\x00\x06',
		"LOW_PASS_FILTER_SLOPE":b'\x04\x00\x00\x00\x0c\x00\x02',
		"LFE":b'\x04\x00\x00\x00\x08\x00\x02',
		"LOW_PASS_FILTER_FREQ":b'\x04\x00\x00\x00\x0a\x00\x02',
		"ROOM_GAIN_ALL_SETTINGS":b'\x04\x00\x00\x00\x26\x00\x06',
		"ROOM_GAIN_ENABLE":b'\x04\x00\x00\x00\x26\x00\x02', 
		"ROOM_GAIN_FREQ":b'\x04\x00\x00\x00\x28\x00\x02',
		"ROOM_GAIN_SLOPE":b'\x04\x00\x00\x00\x2a\x00\x02',
        "POWER_SETTING":b'\x04\x00\x00\x00\x04\x00\x02',
		"PARAM_3":b'\x04\x00\x00\x00\x00\x00\x32',
		"PARAM_4":b'\x08\x00\x00\x00\x00\x00\x08',
		"PARAM_5": b'\x09\x00\x00\x00\x00\x00\x08',
		"PARAM_6":b'\x0a\x00\x00\x00\x00\x00\x08'
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
        if SVS_PARAMS["VOLUME"] in FULL_FRAME:
            print("<- Received VOLUME data (Handle %s):  %s" % (hex(handle), hexlify(FULL_FRAME)))
            vol_slider.set(hex2volume_slider_position(FULL_FRAME))
        elif SVS_PARAMS["PHASE"] in FULL_FRAME:
            print("<- Received PHASE data (Handle %s):  %s" % (hex(handle), hexlify(FULL_FRAME)))
            phase_slider.set(hex2phase_slider_position(FULL_FRAME))
        elif SVS_PARAMS["LFE"] in FULL_FRAME:
            print("<- Received LFE ON/OFF data (Handle %s):  %s" % (hex(handle), hexlify(FULL_FRAME)))
            lfe_var.set(hex2lfe_state(FULL_FRAME))
            refresh_conditional_widgets()
        elif SVS_PARAMS["LOW_PASS_FILTER_FREQ"] in FULL_FRAME:
            print("<- Received LOW PASS FILTER FREQUENCY data (Handle %s):  %s" % (hex(handle), hexlify(FULL_FRAME)))
            lpfilter_slider.set(hex2lpfilter_slider_position(FULL_FRAME))
        elif SVS_PARAMS["LOW_PASS_FILTER_SLOPE"] in FULL_FRAME:
            print("<- Received LOW PASS FILTER SLOPE data (Handle %s):  %s" % (hex(handle), hexlify(FULL_FRAME)))
            lpfilter_slope_combo.current(hex2lpfilter_slope_combo_position(FULL_FRAME))
        elif SVS_PARAMS["LOW_PASS_FILTER_ALL_SETTINGS"] in FULL_FRAME:
            print("<- Received LOW PASS FILTER FULL_SETTINGS data (Handle %s):  %s" % (hex(handle), hexlify(FULL_FRAME)))
            lpfilter_slider.set(hex2lpfilter_slider_position(FULL_FRAME))
            lpfilter_slope_combo.current(hex2lpfilter_slope_combo_position(FULL_FRAME))
            lfe_var.set(hex2lfe_state(FULL_FRAME))
            refresh_conditional_widgets()
        elif SVS_PARAMS["ROOM_GAIN_ENABLE"] in FULL_FRAME:
            print("<- Received ROOM GAIN ON/OFF data (Handle %s):  %s" % (hex(handle), hexlify(FULL_FRAME)))
            room_gain_var.set(hex2room_gain_state(FULL_FRAME))
            refresh_conditional_widgets()
        elif SVS_PARAMS["ROOM_GAIN_FREQ"] in FULL_FRAME:
            print("<- Received ROOM GAIN FREQUENCY data (Handle %s):  %s" % (hex(handle), hexlify(FULL_FRAME)))
            room_gain_slider.set(hex2room_gain_freq(FULL_FRAME))
        elif SVS_PARAMS["ROOM_GAIN_SLOPE"] in FULL_FRAME:
            print("<- Received ROOM GAIN SLOPE data (Handle %s):  %s" % (hex(handle), hexlify(FULL_FRAME)))
            room_gain_slope_combo.current(hex2room_gain_slope_combo_position(FULL_FRAME))
        elif SVS_PARAMS["ROOM_GAIN_ALL_SETTINGS"] in FULL_FRAME:
            print("<- Received ROOM GAIN FULL SETTINGS data (Handle %s):  %s" % (hex(handle), hexlify(FULL_FRAME)))
            room_gain_slider.set(hex2room_gain_freq(FULL_FRAME))
            room_gain_slope_combo.current(hex2room_gain_slope_combo_position(FULL_FRAME))
            room_gain_var.set(hex2room_gain_state(FULL_FRAME))
            refresh_conditional_widgets()
        elif SVS_PARAMS["POWER_SETTING"] in FULL_FRAME:
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
        await asyncio.sleep(0,1)
        await client.write_gatt_char(char_uuid, svs("ASK", "LOW_PASS_FILTER_ALL_SETTINGS"))
        await asyncio.sleep(0,1)
        await client.write_gatt_char(char_uuid, svs("ASK", "ROOM_GAIN_ALL_SETTINGS"))
        await asyncio.sleep(0,1)

        while RUN_THREAD:
        #don't let this method die in order to RX continuosly
             if len(TX.BUFFER) > 0: 
                 await client.write_gatt_char(char_uuid, TX.BUFFER)
                 TX.BUFFER = ""
             await asyncio.sleep(0.2)
        print("Bleak Client Thread closed")

def svs(command, param, data=b'\x00'):
   frame = SVS_COMMANDS[command] + SVS_PARAMS[param] + data
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

def crc(str):
    crc = 0
    for c in str:
        crc = _update_crc(crc, ord(c))
    return crc

def crcb(*i):
    crc = 0
    for c in i:
        crc = _update_crc(crc, c)
    return crc
########### End CRC16 XMODEM Routines #################


###############   GUI Routines   ######################

def update_vol(self):
    TX.BUFFER = svs("SET","VOLUME",data2hex(vol_slider.get(), VOL_REF))

def update_phase(self):
    TX.BUFFER = svs("SET","PHASE",data2hex(phase_slider.get(), 0))

def lfe_opt_changed():
    refresh_conditional_widgets()
    TX.BUFFER = svs("SET","LFE",data2hex(not(lfe_var.get()), 0))

def update_lpfilter_freq(self):
    if not lfe_var.get():
    #as this callback is called when the click is released, be sure only to send svs set only if lfe = off
        TX.BUFFER = svs("SET","LOW_PASS_FILTER_FREQ",data2hex(lpfilter_slider.get(), 0))

def update_lpfilter_slope(self):
    TX.BUFFER = svs("SET","LOW_PASS_FILTER_SLOPE",data2hex(LP_SLOPE_LIMITS[lpfilter_slope_combo.current()], 0))

def room_gain_opt_changed():
    refresh_conditional_widgets()
    TX.BUFFER = svs("SET","ROOM_GAIN_ENABLE", data2hex(room_gain_var.get(), 0))

def update_room_gain_freq(self):
    if room_gain_var.get():
    #as this callback is called when the click is released, be sure only to send svs set only if room_gain = on
        TX.BUFFER = svs("SET","ROOM_GAIN_FREQ", data2hex(room_gain_slider.get(), 0))

def update_room_gain_slope(self):
    TX.BUFFER = svs("SET","ROOM_GAIN_SLOPE", data2hex(ROOM_GAIN_SLOPE_LIMITS[room_gain_slope_combo.current()], 0))

def make_discrete_slider(value):
    new_value = min(ROOM_GAIN_FREQ_LIMITS, key=lambda x:abs(x-float(value)))
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
def data2hex(level, reference):
    value_hex = (STEP*int(level) + reference).to_bytes(4, 'little')
    return value_hex[:3]

def hex2volume_slider_position(data):
    vol_abs = 16*16*16*16*data[18] + 16*16*data[17] + data[16]
    if (vol_abs - VOL_REF)/STEP in range(VOL_LIMITS[0], VOL_LIMITS[1]):
        vol = (vol_abs - VOL_REF)/STEP
    elif vol_abs == 0:
        vol = VOL_LIMITS[1]
    else:
        print("Unrecognized volume values received")
    return vol

def hex2phase_slider_position(data):
    phase_abs = 16*16*16*16*data[18] + 16*16*data[17] + data[16]
    if phase_abs/STEP in range(PHASE_LIMITS[0],PHASE_LIMITS[1] + 1):
        phase = phase_abs/STEP
    else:
        print("Unrecognized phase values received")
    return phase

def hex2lfe_state(data):
    lfe_abs = 16*16*16*16*data[18] + 16*16*data[17] + data[16]
    if lfe_abs in LFE_LIMITS:
        lfe = not(bool(lfe_abs))
    else:
        print("Unrecognized LFE option value received")
    return lfe

def hex2lpfilter_slider_position(data):
    if len(data) == 35:
        lpfreq_abs = 16*16*16*16*data[20] + 16*16*data[19] + data[18]
    else:
        lpfreq_abs = 16*16*16*16*data[18] + 16*16*data[17] + data[16]
    if lpfreq_abs/STEP in range(LP_FREQ_LIMITS[0], LP_FREQ_LIMITS[1] + 1):
        freq = lpfreq_abs / STEP
    else:
        print("Unrecognized Low Pass Filter Frequency values received")
    return int(freq)

def hex2lpfilter_slope_combo_position(data):
    if len(data) == 35:
        slope_abs = 16*16*data[21]
    else:
        slope_abs = 16*16*data[17] + data[16]
    if int(slope_abs/STEP) in LP_SLOPE_LIMITS:
        slope = LP_SLOPE_LIMITS.index(int(slope_abs/STEP))
    else:
        print("Unrecognized low pass filter slope values received")
    return slope

def hex2room_gain_state(data):
    room_gain_abs = 16*16*16*16*data[18] + 16*16*data[17] + data[16]
    if room_gain_abs in ROOM_GAIN_LIMITS:
        room_gain = bool(room_gain_abs)
    else:
        print("Unrecognized room gain option value received")
    return room_gain

def hex2room_gain_freq(data):
    if len(data) == 35:
        freq_abs = 16*16*16*16*data[20] + 16*16*data[19] + data[18]
    else:
        freq_abs = 16*16*16*16*data[18] + 16*16*data[17] + data[16]
    if freq_abs / STEP in ROOM_GAIN_FREQ_LIMITS:
        freq = freq_abs / STEP
    else:
        print("Unrecognized room gain frequency values received")
    return int(freq)

def hex2room_gain_slope_combo_position(data):
    if len(data) == 35:
        slope_abs = 16*16*data[21]
    else:
        slope_abs = 16*16*data[17] + data[16]
    if int(slope_abs / STEP) in ROOM_GAIN_SLOPE_LIMITS:
        slope = ROOM_GAIN_SLOPE_LIMITS.index(int(slope_abs / STEP))
    else:
        print("Unrecognized room gain slope values received")
    return slope


###########   End AUX Routines   ###################

###############   main()   ##########################

if __name__ == "__main__":
    try:
        window = Tk()
        window.protocol("WM_DELETE_WINDOW", on_closing)
        window.title("pySVS v.2.2 Beta - SVS Subwoofer Control")
        window.geometry('550x400')
        window.resizable(False, False)
        style= ttk.Style()
        style.map("TCombobox", fieldbackground=[("readonly", "white"),("disabled", "gray") ])
        window.columnconfigure(16, weight=1)
        window.rowconfigure(16, weight=1)

        vol_slider = Scale(window, from_=VOL_LIMITS[0], to=VOL_LIMITS[1], label = "Volume (dB)", orient=HORIZONTAL, resolution=1, length=200)
        vol_slider.grid(column=4, row=3, padx = 20, pady = 15)
        vol_slider.bind("<ButtonRelease-1>", update_vol)

        phase_slider = Scale(window, from_=PHASE_LIMITS[0], to=PHASE_LIMITS[1], label = "Phase (°)", orient=HORIZONTAL, resolution=1, length=200)
        phase_slider.grid(column=4, row=5, padx = 20, pady = 15)
        phase_slider.bind("<ButtonRelease-1>", update_phase)

        lpfilter_slider = Scale(window, from_=LP_FREQ_LIMITS[0], to=LP_FREQ_LIMITS[1], label = "Low Pass Freq. (Hz)", orient=HORIZONTAL, resolution=1, length=200)
        lpfilter_slider.grid(column=4, row=7, padx = 20, pady = 15)
        lpfilter_slider.bind("<ButtonRelease-1>", update_lpfilter_freq)
        lpfilter_slope_combo=ttk.Combobox(window,values=[str(i) + " dB" for i in LP_SLOPE_LIMITS],width=7,state='readonly')
        lpfilter_slope_combo.grid(column=5, row=7)
        lpfilter_slope_combo.bind("<<ComboboxSelected>>", update_lpfilter_slope)
        lfe_var = BooleanVar(value=False)
        lfe_checkbox = ttk.Checkbutton(variable=lfe_var, command=lfe_opt_changed)
        lfe_checkbox.grid(sticky="W", column=6, row=7)

        room_gain_slider = Scale(window, from_=min(ROOM_GAIN_FREQ_LIMITS), to=max(ROOM_GAIN_FREQ_LIMITS), label = "Room Gain Freq. (Hz)", orient=HORIZONTAL, resolution=1, length=200, command=make_discrete_slider)
        room_gain_slider.bind("<ButtonRelease-1>", update_room_gain_freq)
        room_gain_slider.grid(column=4, row=9, padx = 20, pady = 15)
        room_gain_slope_combo=ttk.Combobox(window,values=[str(i) + " dB" for i in ROOM_GAIN_SLOPE_LIMITS],width=7,state='readonly')
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
	
    except Exception as e:
        print(e)
