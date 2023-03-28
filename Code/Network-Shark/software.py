#!/usr/bin/python
from secrets import token_hex
from tkinter import BOTTOM, IntVar
import customtkinter as ct
import tkinter.messagebox as tkmb
import tkinter as tk
from tkinter.filedialog import askdirectory, askopenfilename
import PyPDF2
import pyshark
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import numpy as np
from fpdf import *
import os
from PIL import Image
from tkintermapview import TkinterMapView
from Crypto.Util.number import bytes_to_long, long_to_bytes
from base64 import b64encode, b64decode
from ip2geotools.databases.noncommercial import DbIpCity
from geopy.distance import distance
ct.set_appearance_mode("dark")
ct.set_default_color_theme("dark-blue")


def login():
    def validateLogin():
        with open('application_files/cosmic.txt') as file:
            line = file.read()
            final = b64decode(long_to_bytes(int(line,16))).decode()
            words = final.split('\n')        
        if(username_entry.get() == words[0] and password_entry.get() == words[1]):
            user_name_str = username_entry.get()
            login_window.destroy()
            app = App()
            app.mainloop()
        else:
            tkmb.showerror(title="Login Failed",message="Invalid Username and password")
    def show_and_hide():
        if(checkbox.get()==1):
            password_entry.configure(show='')
        else:
            password_entry.configure(show='*')   
    image_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_images")  
    login_window = ct.CTk()
    login_window.geometry("500x350")
    login_window.title("Login")
    frame = ct.CTkFrame(master=login_window)
    frame.pack(pady=20,padx=60,fill="both",expand=True)
    logo_image = ct.CTkImage(Image.open(os.path.join(image_path, "tnpl.png")), size=(26, 26))
    label = ct.CTkLabel(frame, text="  TN Police", image=logo_image,compound="left", font=ct.CTkFont(size=15, weight="bold"))
    label.pack(pady=12,padx=10)
    username_entry = ct.CTkEntry(master=frame,placeholder_text="Username")
    username_entry.pack(pady=12,padx=10)
    password_entry = ct.CTkEntry(master=frame,placeholder_text="Password",show="*")
    password_entry.pack(pady=12,padx=10)
    button = ct.CTkButton(master=frame, text="Login",command=validateLogin)
    button.pack(pady=12,padx=10)
    checkbox = ct.CTkCheckBox(master=frame,text="Show password",command=show_and_hide)
    checkbox.pack(pady=12,padx=10)
    login_window.mainloop()
    
class App(ct.CTk):
    def __init__(self):
        super().__init__()

        self.title("Network Shark")
        self.geometry("1100x760")
        image_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_images")
        self.icon = tk.PhotoImage(file = os.path.join(image_path,"logo.png"))
        self.iconphoto(False,self.icon)
        # set grid layout 1x2
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # load images with light and dark mode image
        
        self.logo_image = ct.CTkImage(Image.open(os.path.join(image_path, "tnpl.png")), size=(26, 26))
        self.large_test_image = ct.CTkImage(Image.open(os.path.join(image_path, "large_test_image_new.png")), size=(500, 150))
        self.image_icon_image = ct.CTkImage(Image.open(os.path.join(image_path, "image_icon_light.png")), size=(20, 20))
        self.home_image = ct.CTkImage(light_image=Image.open(os.path.join(image_path, "home_dark.png")),
                                                 dark_image=Image.open(os.path.join(image_path, "home_light.png")), size=(20, 20))
        self.brush_image = ct.CTkImage(light_image=Image.open(os.path.join(image_path, "brush.png")),
                                                 dark_image=Image.open(os.path.join(image_path, "brush_dark.png")), size=(20, 20))
        self.add_user_image = ct.CTkImage(light_image=Image.open(os.path.join(image_path, "add_user_dark.png")),
                                                     dark_image=Image.open(os.path.join(image_path, "add_user_light.png")), size=(20, 20))
        self.decrypt_image = ct.CTkImage(light_image=Image.open(os.path.join(image_path, "decrypt.png")),
                                                  dark_image=Image.open(os.path.join(image_path, "decrypt_dark.png")), size=(20, 20))
        self.decode_image = ct.CTkImage(light_image=Image.open(os.path.join(image_path, "mglass_dark.png")),
                                                     dark_image=Image.open(os.path.join(image_path, "mglass_light.png")), size=(20, 20))
        # create navigation frame
        self.navigation_frame = ct.CTkFrame(self, corner_radius=0)
        self.navigation_frame.grid(row=0, column=0, sticky="nsew")
        self.navigation_frame.grid_rowconfigure(7, weight=1)

        self.navigation_frame_label = ct.CTkLabel(self.navigation_frame, text="  TN Police", image=self.logo_image,
                                                             compound="left", font=ct.CTkFont(size=15, weight="bold"))
        self.navigation_frame_label.grid(row=0, column=0, padx=20, pady=20)

        self.home_button = ct.CTkButton(self.navigation_frame, corner_radius=0, height=40, border_spacing=10, text="Home",
                                                   fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                   image=self.home_image, anchor="w", command=self.home_button_event)
        self.home_button.grid(row=1, column=0, sticky="ew")

        self.clear_cache_button = ct.CTkButton(self.navigation_frame, corner_radius=0, height=40, border_spacing=10, text="Clear cache",
                                                      fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                      image=self.brush_image, anchor="w", command=self.clear_cache_button_event)
        self.clear_cache_button.grid(row=2, column=0, sticky="ew")

        self.password_change_button = ct.CTkButton(self.navigation_frame, corner_radius=0, height=40, border_spacing=10, text="Change credentials",
                                                      fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                      image=self.add_user_image, anchor="w", command=self.password_change_button_event)
        self.password_change_button.grid(row=3, column=0, sticky="ew")

        self.decrypt_srtp_button = ct.CTkButton(self.navigation_frame, corner_radius=0, height=40, border_spacing=10, text="Decrypt SRTP",
                                                      fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                      image=self.decrypt_image, anchor="w", command=self.decrypt_srtp_button_event)
        self.decrypt_srtp_button.grid(row=4, column=0, sticky="ew")

        self.decode_to_audio_button = ct.CTkButton(self.navigation_frame, corner_radius=0, height=40, border_spacing=10, text="Decode Audio",
                                                      fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                      image=self.decode_image, anchor="w", command=self.decode_to_audio_button_event)
        self.decode_to_audio_button.grid(row=5, column=0, sticky="ew")

        self.geolocation_button = ct.CTkButton(self.navigation_frame, corner_radius=0, height=40, border_spacing=10, text="Geolocation",
                                                      fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                      image=self.decode_image, anchor="w", command=self.geolocation_button_event)
        self.geolocation_button.grid(row=6, column=0, sticky="ew")
        self.appearance_mode_menu = ct.CTkOptionMenu(self.navigation_frame, values=["Light", "Dark", "System"],
                                                                command=self.change_appearance_mode_event)
        self.appearance_mode_menu.grid(row=9, column=0, padx=20, pady=20, sticky="s")

        self.exit = ct.CTkButton(self.navigation_frame,text="Exit",command=lambda: self.destroy(),width=100)
        self.exit.grid(row=8,column=0,padx=20,pady=10)

        # create home frame
        
        self.home_frame = ct.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.home_frame.grid_columnconfigure(0, weight=1)

        self.home_frame_large_image_label = ct.CTkLabel(self.home_frame, text="", image=self.large_test_image)
        self.home_frame_large_image_label.grid(row=0, column=0, padx=20, pady=10)
        
        def open_pcap():            
                filename = askopenfilename(title="Select the capture file",filetypes=[("Capture files", ".pcap .pcapng")])
                pcap_file_label.configure(text="File Opened: "+filename)
                pcap_path = filename
                filtered_cap_tcp = pyshark.FileCapture(pcap_path, display_filter="tcp")
                filtered_cap_udp = pyshark.FileCapture(pcap_path, display_filter="udp")
                filtered_cap_sip = pyshark.FileCapture(pcap_path, display_filter="sip")
                filtered_cap_sdp = pyshark.FileCapture(pcap_path, display_filter="sdp")
                filtered_cap_rtp = pyshark.FileCapture(pcap_path, display_filter="rtp")
                filtered_cap_rtcp = pyshark.FileCapture(pcap_path, display_filter="rtcp")
                filtered_cap_tls = pyshark.FileCapture(pcap_path, display_filter="tls")
                def run(pcap_path):
                    gen.configure(text="Wait for response...")
                    def run_more():
                        if(check_var1 ==0 and check_var1 == 0 and check_var2 == 0 and check_var3 == 0 and check_var4 == 0):
                            tkmb.showerror(title="Error",message="No options were selected")
                        else: 
                            case_name = case_entry.get()
                            def dest_window():
                                def open_dest():
                                    directory = askdirectory()
                                    dest_file_label.configure(text=f"Destination: {directory}")
                                    success_label = ct.CTkLabel(master=dest_window,text="")
                                    success_label.grid(row=2,column=0,padx=20,pady=10) 
                                    try:
                                        os.system(f"mv cache_files/finalreport.pdf {directory}/{case_name}.pdf")
                                        success_label.configure(text="File saved in the destination")
                                        dest_window.lift()
                                        ok = ct.CTkButton(master=dest_window,text="Ok",command=lambda: dest_window.destroy())
                                        ok.grid(row=3,column=0,padx=20,pady=10) 
                                    except:
                                        success_label.configure(text="Something went wrong! Try Again!")
                                        dest_window.lift()
                                        os.system("rm cache_files/finalreport.pdf")
                                        ok = ct.CTkButton(master=dest_window,text="Ok",command=lambda: dest_window.destroy())
                                        ok.grid(row=3,column=0,padx=20,pady=10)             
                                dest_window = ct.CTk()
                                dest_window.geometry("500x250")
                                dest_window.grid_columnconfigure(0, weight=1)
                                dest_window.lift()
                                dest_window.title("Specify Destination")
                                dest_file_label = ct.CTkLabel(master=dest_window,text="Please specify the destination folder to save the report.")
                                dest_file_btn = ct.CTkButton(master=dest_window, text ='Browse', command= open_dest)
                                dest_file_label.grid(row=0,column=0,padx=20,pady=10)
                                dest_file_btn.grid(row=1,column=0,padx=20,pady=10)                      
                            # gen= ct.CTkLabel(master=self.home_frame,text="Generating...Please hold still...")
                            # gen.grid(row=10, column=0, padx=20, pady=10)
                            gen.configure(text="Generating...Please hold still...")                    
                            bar = ct.CTkProgressBar(master=self.home_frame,width=500)
                            bar.grid(row=11, column=0, padx=20, pady=10)
                            def check_checkbuttom_vals():
                                val = 0
                                if(check_var1.get()):
                                    filtered_cap_tcp.load_packets()
                                    filtered_cap_udp.load_packets()
                                    with PdfPages('cache_files/report1.pdf') as pdf:
                                        no_of_tcp,no_of_udp = len(filtered_cap_tcp),len(filtered_cap_udp)
                                        list_of_types = {'TCP':no_of_tcp,'UDP':no_of_udp}
                                        lsizes= []
                                        labels=[]
                                        colors = ['#e41a1c','#377eb8','#4daf4a','#984ea3','#ff7f00','#ffff33','#a65628','#f781bf']                                       
                                        explode =[]
                                        for label,size in list_of_types.items():
                                            if size != 0:
                                                lsizes.append(size)
                                                labels.append(label)
                                                explode.append(0)
                                        explode[0] = 0.1
                                        patches,texts = plt.pie(lsizes, explode=explode, colors=colors,radius=1.2,shadow=True, startangle=90)
                                        y = np.array(lsizes)
                                        percent = 100.*y/y.sum()
                                        plabels = ['{0} - {1:1.2f} %'.format(i,j) for i,j in zip(labels, percent)]
                                        sort_legend = True
                                        if sort_legend:
                                            patches, plabels, dummy =  zip(*sorted(zip(patches, plabels, y),
                                                                                key=lambda x: x[2],
                                                                                reverse=True))

                                        plt.legend(patches, plabels, loc='right', bbox_to_anchor=(-0.1, 1.),
                                                fontsize=8)
                                        plt.title("TCP/UDP PACKET COMPOSITION CHART",loc="center")
                                        pdf.savefig()
                                        plt.close()  
                                    val+=0.2  
                                    bar.set(val)  
                                    self.appearance_mode_menu.update_idletasks()
                                    gen.configure(text="Ya it's generating....")
                                if(check_var2.get()):
                                    filtered_cap_sip.load_packets()
                                    filtered_cap_sdp.load_packets()
                                    filtered_cap_rtp.load_packets()
                                    filtered_cap_rtcp.load_packets()
                                    filtered_cap_tls.load_packets()
                                    global no_of_sip,no_of_sdp,no_of_rtp,no_of_rtcp,no_of_tls
                                    no_of_sip,no_of_sdp,no_of_rtp,no_of_rtcp,no_of_tls = len(filtered_cap_sip),len(filtered_cap_sdp),len(filtered_cap_rtp),len(filtered_cap_rtcp),len(filtered_cap_tls)
                                    with PdfPages('cache_files/report2.pdf') as pdf:
                                        list_of_types = {'SIP':no_of_sip,'SDP':no_of_sdp,'RTP':no_of_rtp,'RTCP':no_of_rtcp,'TLS':no_of_tls}
                                        lsizes= []
                                        labels=[]
                                        colors = ['#e41a1c','#377eb8','#4daf4a','#984ea3','#ff7f00','#ffff33','#a65628','#f781bf']
                                        explode =[]
                                        for label,size in list_of_types.items():
                                            if size != 0:
                                                lsizes.append(size)
                                                labels.append(label)
                                                explode.append(0)
                                        explode[0] = 0.1
                                        y = np.array(lsizes)
                                        percent = 100.*y/y.sum()
                                        patches, texts = plt.pie(y,explode=explode, colors=colors, startangle=90, radius=1.2)
                                        plabels = ['{0} - {1:1.2f} %'.format(i,j) for i,j in zip(labels, percent)]
                                        sort_legend = True
                                        if sort_legend:
                                            patches, plabels, dummy =  zip(*sorted(zip(patches, plabels, y),
                                                                                key=lambda x: x[2],
                                                                                reverse=True))

                                        plt.legend(patches, plabels, loc='right', bbox_to_anchor=(-0.1, 1.),
                                                fontsize=8)
                                        plt.title("VOIP PACKET COMPOSITION CHART",loc="center")
                                        pdf.savefig()
                                        plt.close()
                                    val+=0.2
                                    bar.set(val)  
                                    self.appearance_mode_menu.update_idletasks()
                                    gen.configure(text="Have a sip of water...")
                                if(check_var3.get()):
                                    
                                    data = [("S.no.","Highest layer","Interface name","User name","Source IP","Source Port","Source MAC","From Tag","Destination IP","Destination MAC","Destination port","To Tag","Time","Sniffed Timestamp","Call ID","TTL","Length","Packet method","Content type","User agent")]
                                    sdp_data = [("S.no","Session_Name","Protocol","Media Attribute","Media format","Media port","FMTP_parameter")]
                                    j=0
                                    for packet in filtered_cap_sip:
                                        try:
                                            content_type = str(packet.sip.content_type)
                                        except:
                                            content_type = str(None)  
                                        try:
                                            to_tag = str(packet.sip.to_tag)
                                        except:
                                            to_tag = str(None)  
                                        try:
                                            sip_user_agent = str(packet.sip.user_agent)
                                        except:
                                            sip_user_agent = str(None)  
                                        try:
                                            sdp_session_name = str(packet.sip.sdp_session_name)
                                            sdp_present = 1
                                            try:
                                                sdp_media_proc = str(packet.sip.sdp_media_proto)
                                            except:
                                                sdp_media_proc = str(None)  
                                            try:
                                                sdp_media_attr = str(packet.sip.sdp_media_attr)
                                            except:
                                                sdp_media_attr = str(None)  
                                            try:
                                                sdp_media_format = str(packet.sip.sdp_media_format)
                                            except:
                                                sdp_media_format = str(None)  
                                            try:
                                                sdp_media_port = str(packet.sip.sdp_media_port)
                                            except:
                                                sdp_media_port = str(None)  
                                            try:
                                                sdp_fmtp_parameter = str(packet.sip.sdp_fmtp_parameter)
                                            except:
                                                sdp_fmtp_parameter = str(None)  
                                        except:
                                            sdp_present = 0
                                        try:
                                            packet_length = str(packet.length)
                                        except:
                                            packet_length = str(None)  
                                        try:
                                            packet_method = str(packet.sip.cseq)
                                        except:
                                            packet_method = str(None)  
                                        try:
                                            sip_call_id = str(packet.sip.call_id)
                                        except:
                                            sip_call_id = str(None)  
                                        try:
                                            interface_name = str(packet.frame_info.interface_name)
                                        except:
                                            interface_name = str(None)  
                                        try:
                                            highest_layer = str(packet.highest_layer)
                                        except:
                                            highest_layer = str(None)  
                                        try:
                                            sip_from_user= str(packet.sip.from_user)
                                        except:
                                            sip_from_user = str(None)            
                                        try:
                                            source_ip = str(packet['ip'].src)
                                        except:
                                            source_ip = str(None)  
                                        try:
                                            UDP_source_port = str(packet.udp.srcport)
                                        except:
                                            UDP_source_port = str(None)  
                                        try:
                                            mac_source = str(packet['eth'].src)
                                        except:
                                            mac_source = str(None)  
                                        try:
                                            sip_from_tag = str(packet.sip.from_tag)
                                        except:
                                            sip_from_tag = str(None)  
                                        try:
                                            destination_ip = str(packet['ip'].dst)
                                        except:
                                            destination_ip = str(None)  
                                        try:
                                            mac_destination = str(packet['eth'].dst)
                                        except:
                                            mac_destination = str(None)   
                                        try:
                                            UDP_dest_port = str(packet.udp.dstport)     
                                        except:
                                            UDP_dest_port = str(None)   
                                        try:
                                            ttl = str(packet['ip'].ttl)
                                        except:
                                            ttl = str(None)  
                                        try:
                                            frame_time = str(packet.frame_info.time)
                                        except:
                                            frame_time = str(None)     
                                        try:
                                            sniffed_timestamp = str(packet.sniff_timestamp)
                                        except:
                                            sniffed_timestamp = str(None)     
                                        if sdp_present==1:
                                            data = data + [(str(j),highest_layer,interface_name,sip_from_user,source_ip,UDP_source_port,mac_source,sip_from_tag,destination_ip,mac_destination,UDP_dest_port,to_tag,frame_time,sniffed_timestamp,sip_call_id,ttl,packet_length,packet_method,content_type,sip_user_agent)]
                                            #output += f"{j}. | {highest_layer} | {interface_name}: | FROM User: {sip_from_user}@{source_ip} PORT:{UDP_source_port} MAC:{mac_source}  Tag:{sip_from_tag} | TO | {destination_ip} MAC:{mac_destination} PORT:{UDP_dest_port} Tag:{to_tag} | {frame_time} | Sniffed_timestamp:{sniffed_timestamp} | Call_ID: {sip_call_id} | TTL: {ttl} | Packet_Length:{packet_length} | Method:{packet_method} | Content-type:{content_type} | User_Agent:{sip_user_agent}   SDP Info: Session_Name:{sdp_session_name} | Protocol:{sdp_media_proc} | Media_Attribute:{sdp_media_attr} | Media_format:{sdp_media_format} | Media_port:{sdp_media_port} | FMTP_parameter:{sdp_fmtp_parameter}\n"
                                            sdp_data = sdp_data + [(str(j),sdp_session_name, sdp_media_proc,sdp_media_attr,sdp_media_format,sdp_media_port,sdp_fmtp_parameter)]                                            
                                            j+=1
                                        else:
                                            data = data + [(str(j),highest_layer,interface_name,sip_from_user,source_ip,UDP_source_port,mac_source,sip_from_tag,destination_ip,mac_destination,UDP_dest_port,to_tag,frame_time,sniffed_timestamp,sip_call_id,ttl,packet_length,packet_method,content_type,sip_user_agent)]
                                            #output += f"{j}. | {highest_layer} | {interface_name}: | FROM User: {sip_from_user}@{source_ip} PORT:{UDP_source_port} MAC:{mac_source}  Tag:{sip_from_tag} | TO | {destination_ip} MAC:{mac_destination} PORT:{UDP_dest_port} Tag:{to_tag} | {frame_time} | Sniffed_timestamp:{sniffed_timestamp} | Call_ID: {sip_call_id} | TTL: {ttl} | Packet_Length:{packet_length} | Method:{packet_method} | Content-type:{content_type} | User_Agent:{sip_user_agent}\n"
                                            j+=1
                                    data = tuple(data)
                                    sdp_data = tuple(sdp_data)
                                    pdf = FPDF(format="legal",orientation="landscape")
                                    pdf.add_page()
                                    pdf.set_font("Times", size=5)
                                    line_height = pdf.font_size * 2.5
                                    col_width = pdf.epw / 20  # distribute content evenly
                                    pdf.multi_cell(w=0,txt="SIP REPORT",border=1,h=8,new_x=XPos.LMARGIN,new_y=YPos.NEXT)
                                    for row in data:
                                        for datum in row:
                                            pdf.multi_cell(col_width, line_height, datum, border=1,
                                                    new_x="RIGHT", new_y="TOP", max_line_height=pdf.font_size)
                                        pdf.ln(line_height)
                                    pdf.add_page()
                                    pdf.set_font("Times", size=5)
                                    line_height = pdf.font_size * 2.5
                                    col_width = pdf.epw / 7  # distribute content evenly
                                    pdf.multi_cell(w=0,txt="SDP report",border=1,h=8,new_x=XPos.LMARGIN,new_y=YPos.NEXT)
                                    for row in sdp_data:
                                        for datum in row:
                                            pdf.multi_cell(col_width, line_height, datum, border=1,
                                                    new_x="RIGHT", new_y="TOP", max_line_height=pdf.font_size)
                                        pdf.ln(line_height)
                                    pdf.output("cache_files/report3.pdf")
                                    val+=0.2
                                    bar.set(val)  
                                    self.appearance_mode_menu.update_idletasks()
                                    gen.configure(text="Be patient...")
                                if(check_var4.get()):
                                    count_invite = 0
                                    output = ""
                                    sender_ip = ''
                                    receiver_ip = ''
                                    for packet in filtered_cap_sip:
                                        if(packet.sip.cseq_method == 'INVITE' and packet.sip.field_names[0] != 'status_line' and packet.ip.src != sender_ip and packet.ip.dst != receiver_ip):
                                            count_invite += 1
                                            sender_ip = packet.ip.src
                                            receiver_ip = packet.ip.dst
                                            start_time = packet.frame_info.time_relative #packet.udp.time_relative 
                                            new_cap = pyshark.FileCapture(pcap_path, display_filter=f"sip && ip.src == {sender_ip} && ip.dst == {receiver_ip}")
                                            new_cap.load_packets()
                                            for packet in new_cap:
                                                if(packet.sip.cseq_method == 'BYE'):
                                                    stop_time = packet.frame_info.time_relative
                                            total_time = float(stop_time) - float(start_time)
                                            output += f"Packet stream from {sender_ip} to {receiver_ip} has a call duration of {total_time} ==> START: {start_time} and STOP: {stop_time}\n"
                                    pdf = FPDF(format="legal",orientation="landscape")
                                    pdf.add_page()
                                    pdf.set_font("Arial",size=12)
                                    pdf.multi_cell(w=0,txt="CALL DURATION REPORT",border=1,h=10)
                                    pdf.multi_cell(w=0,txt =output,border=1,h=10)
                                    pdf.output("cache_files/report4.pdf") 
                                    val+=0.2
                                    bar.set(val)  
                                    self.appearance_mode_menu.update_idletasks()
                                    gen.configure(text="Almost done...")
                                if(1):
                                    files = []
                                    if(check_var1.get()):
                                        files.append('cache_files/report1.pdf')
                                    if(check_var2.get()):
                                        files.append('cache_files/report2.pdf')
                                    if(check_var3.get()):
                                        files.append('cache_files/report3.pdf')
                                    if(check_var4.get()):
                                        files.append('cache_files/report4.pdf')                                
                                    pdfMerge = PyPDF2.PdfMerger()
                                    if(len(files)>0):
                                        for file in files:
                                            pdfFile=open(file,'rb')
                                            pdfReader = PyPDF2.PdfReader(pdfFile)
                                            pdfMerge.append(pdfReader)
                                        pdfFile.close()
                                        pdfMerge.write('cache_files/finalreport.pdf')
                                    finalval = 1
                                    bar.set(finalval)
                                    self.appearance_mode_menu.update_idletasks()
                                    os.system("rm cache_files/report*.pdf")
                                    #label to set that the file has been generated in the destination    
                                    gen.configure(text="The PDF report has been generated.")
                                    click_to_save = ct.CTkButton(master=self.home_frame,text="Click to save",command=dest_window)
                                    click_to_save.grid(row=12,column=0,padx=20,pady=10)
                            check_checkbuttom_vals()
                    run_more()
                check_var1 = IntVar()
                check_var2 = IntVar()
                check_var3 = IntVar()
                check_var4 = IntVar()
                check_btn1 = ct.CTkCheckBox(master=self.home_frame, text = "TCP/UDP report",
                                        variable=check_var1,
                                        onvalue=1,
                                        offvalue=0,
                                        height=2,
                                        width=10)
                check_btn1.grid(row=5, column=0, padx=20, pady=10)
                check_btn2 = ct.CTkCheckBox(master=self.home_frame, text = "VoIP Packet Composition report",
                                        variable=check_var2,
                                        onvalue=1,
                                        offvalue=0,
                                        height=2,
                                        width=10)
                check_btn2.grid(row=6, column=0, padx=20, pady=10)
                check_btn3 = ct.CTkCheckBox(master=self.home_frame, text = "SIP packet data report",
                                        variable=check_var3,
                                        onvalue=1,
                                        offvalue=0,
                                        height=2,
                                        width=10)
                check_btn3.grid(row=7, column=0, padx=20, pady=10)
                check_btn4 = ct.CTkCheckBox(master=self.home_frame, text = "Duration of the call report",
                                        variable=check_var4,
                                        onvalue=1,
                                        offvalue=0,
                                        height=2,
                                        width=10)
                check_btn4.grid(row=8, column=0, padx=20, pady=10)
                gen= ct.CTkLabel(master=self.home_frame,text="")
                gen.grid(row=10, column=0, padx=20, pady=10)
                analyse_btn = ct.CTkButton(master=self.home_frame,text="Generate report",command=lambda: run(filename))
                analyse_btn.grid(row=9, column=0, padx=20, pady=10)

        case_label = ct.CTkLabel(master=self.home_frame,text="Please specify the case ID: [Avoid invalid symbols]")
        case_label.grid(row=1,column=0,padx=20,pady=10)
        case_entry = ct.CTkEntry(master=self.home_frame,placeholder_text="Case ID",width=200)
        case_entry.grid(row=2,column=0,padx=20,pady=10)
        pcap_file_label = ct.CTkLabel(master=self.home_frame,text="Specify the location of the PCAP file that you want to analyse",width=100,height=4)
        pcap_file_btn = ct.CTkButton(master=self.home_frame, text ='Open', command= open_pcap,width=100)
        pcap_file_label.grid(row=3, column=0, padx=20, pady=10)
        pcap_file_btn.grid(row=4, column=0, padx=20, pady=10)
        #repage = ct.CTkButton(master=self.home_frame,text="Back to Home",command=new_page,hover=True)
        #repage.pack(side=BOTTOM,padx=120,pady=10)   

        # create second frame
        def clear_cache():
            try:
                os.system("rm cache_files/*")
                self.clear_cache_label.configure(text="Cache cleared!")
            except:
                self.clear_cache_button.configure(text="Something went wrong! Please try again.")
                try_again_button = ct.CTkButton(master=self.clear_cache_frame,text="Try again",command=lambda: self.clear_cache_frame())
                try_again_button.grid(row=2,column=0,padx=20,pady=10)
        
        self.clear_cache_frame = ct.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.clear_cache_frame.grid_columnconfigure(0, weight=1)
        self.clear_cache_label = ct.CTkLabel(master=self.clear_cache_frame,text="Click the button to clear the cache stored by this application.")
        self.clear_cache_label.grid(row=0, column=0, padx=20, pady=10)
        self.clear_cache_button_internal = ct.CTkButton(master=self.clear_cache_frame,text="Clear it!",command=clear_cache)
        self.clear_cache_button_internal.grid(row=1, column=0, padx=20, pady=10)
        # create third frame

        def change_creds():
            def show_and_hide():
                if(showPassword.get()==1):
                    pass_show_entry.configure(show='')
                else:
                    pass_show_entry.configure(show='*') 
            def changer():
                try:
                    with open('application_files/cosmic.txt',"r+") as file:
                        username = username_show_entry.get()
                        password = pass_show_entry.get()
                        s = f"{username}\n{password}"
                        final = hex(bytes_to_long(b64encode(s.encode())))
                        file.seek(0)
                        file.write(final)
                        file.truncate()
                        status_mess.configure(text="Credentials changed successfully")
                        file.close()
                except:
                    status_mess.configure(text="Something went wrong!")
            self.change_password_label.grid_forget()
            self.change_password_button.grid_forget()
            message = ct.CTkLabel(master=self.change_password_frame,text="Enter new credentials")
            message.grid(row=1,column=0,padx=20,pady=10)
            username_show_entry = ct.CTkEntry(master=self.change_password_frame,placeholder_text="New Username")
            username_show_entry.grid(row=2,column=0,padx=20,pady=10)
            pass_show_entry = ct.CTkEntry(master=self.change_password_frame,placeholder_text="New Password",show='*')
            submit_btn = ct.CTkButton(master=self.change_password_frame,text="Change",command=changer)
            showPassword = ct.CTkCheckBox(master=self.change_password_frame,text="Show password",command=show_and_hide)
            status_mess = ct.CTkLabel(master=self.change_password_frame,text="")
            pass_show_entry.grid(row=3,column=0,padx=20,pady=10)
            submit_btn.grid(row=4,column=0,padx=20,pady=10)
            status_mess.grid(row=5,column=0,padx=20,pady=10)
            showPassword.grid(row=6,column=0,padx=20,pady=10)

        self.change_password_frame = ct.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.change_password_frame.grid_columnconfigure(0, weight=1)
        self.change_password_label = ct.CTkLabel(master=self.change_password_frame,text="Click the button to change Username or Password")
        self.change_password_label.grid(row=0, column=0, padx=20, pady=10)
        self.change_password_button = ct.CTkButton(master=self.change_password_frame,text="Change username/password",command=change_creds)        
        self.change_password_button.grid(row=1, column=0, padx=20, pady=10)        
        # select default frame
        self.select_frame_by_name("home")


        def open_srtp():
                def decrypt_srtp():
                        def dest_window():
                            def open_dest():
                                directory = askdirectory()
                                dest_file_label.configure(text=f"Destination: {directory}")
                                success_label = ct.CTkLabel(master=dest_window,text="")
                                success_label.grid(row=2,column=0,padx=20,pady=10) 
                                try:
                                    os.system(f"mv {rand}.pcap {directory}/decrypted_srtp_capture.pcap")
                                    success_label.configure(text="File saved in the destination")
                                    dest_window.lift()
                                    ok = ct.CTkButton(master=dest_window,text="Ok",command=lambda: dest_window.destroy())
                                    ok.grid(row=3,column=0,padx=20,pady=10) 
                                except:
                                    success_label.configure(text="Something went wrong! Try Again!")
                                    dest_window.lift()
                                    os.system("rm cache_files/finalreport.pdf")
                                    ok = ct.CTkButton(master=dest_window,text="Ok",command=lambda: dest_window.destroy())
                                    ok.grid(row=3,column=0,padx=20,pady=10)             
                            dest_window = ct.CTk()
                            dest_window.geometry("500x250")
                            dest_window.grid_columnconfigure(0, weight=1)
                            dest_window.lift()
                            dest_window.title("Specify Destination")
                            # icon = tk.PhotoImage(file = os.path.join(image_path,"logo.png"))
                            # dest_window.iconphoto(False,icon)
                            dest_file_label = ct.CTkLabel(master=dest_window,text="Please specify the destination folder to save the report.")
                            dest_file_btn = ct.CTkButton(master=dest_window, text ='Browse', command= open_dest)
                            dest_file_label.grid(row=0,column=0,padx=20,pady=10)
                            dest_file_btn.grid(row=1,column=0,padx=20,pady=10)                     
                        key = str(self.srtp_key_entry.get())
                        try:
                            rand = token_hex(10)
                            os.system(f"./tools/rtp_decoder -a -t 10 -e 128 -b {key} * < {filename} | ./tools/text2pcap -t \"%M:%S.\" -u 10000,10000 - - > cache_files/{rand}.pcap")
                            dest_window()
                        except:
                            tkmb.showerror(title="Failed",message="Something went wrong!")
                filename = askopenfilename(title="Select the capture file",filetypes=[("Capture files", ".pcap .pcapng")])
                self.srtp_pcap_file_label.configure(text="File Opened: "+filename)
                decrypt_srtp_button_internal = ct.CTkButton(master=self.decrypt_srtp_frame,text="Decrypt",command=decrypt_srtp,width=200,height=50)
                decrypt_srtp_button_internal.grid(row=4, column=0, padx=20, pady=10)

        self.decrypt_srtp_frame = ct.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.decrypt_srtp_frame.grid_columnconfigure(0, weight=1)
        self.decrypt_srtp_label = ct.CTkLabel(master=self.decrypt_srtp_frame,text="Enter the key and open filtered SRTP stream capture file.")
        self.decrypt_srtp_label.grid(row=0, column=0, padx=20, pady=10)
        self.srtp_key_entry = ct.CTkEntry(master=self.decrypt_srtp_frame,placeholder_text="key",width=300)
        self.srtp_key_entry.grid(row=1,column=0,padx=20,pady=10)
        self.srtp_pcap_file_label = ct.CTkLabel(master=self.decrypt_srtp_frame,text="File Opened:")
        self.srtp_pcap_file_label.grid(row=2,column=0,padx=20,pady=10)
        self.srtp_pcap_open_button = ct.CTkButton(master=self.decrypt_srtp_frame,text="Open",command=open_srtp)
        self.srtp_pcap_open_button.grid(row=3,column=0,padx=20,pady=10)
        self.additional_info = ct.CTkLabel(master=self.decrypt_srtp_frame,text="* The key would be available in SIP/SDP packets. The capture should be filtered with the IP address of the stream where the key is found")
        self.additional_info.grid(row=6,column=0,padx=20,pady=10)
        self.additional_info1 = ct.CTkLabel(master=self.decrypt_srtp_frame,text="* After decrypting decode it to RTP")
        self.additional_info1.grid(row=7,column=0,padx=20,pady=10)

        def convert_to_audio():
            def dest_window(path):
                            def open_dest():
                                directory = askdirectory()
                                dest_file_label.configure(text=f"Destination: {directory}")
                                success_label = ct.CTkLabel(master=dest_window,text="")
                                success_label.grid(row=2,column=0,padx=20,pady=10) 
                                try:
                                    os.system(f"mv {path}.wav {directory}/audio.wav")
                                    success_label.configure(text="File saved in the destination")
                                    dest_window.lift()
                                    ok = ct.CTkButton(master=dest_window,text="Ok",command=lambda: dest_window.destroy())
                                    ok.grid(row=3,column=0,padx=20,pady=10) 
                                except:
                                    success_label.configure(text="Something went wrong! Try Again!")
                                    dest_window.lift()
                                    os.system(f"rm {path}.wav")
                                    os.system(f"rm {path}.raw")
                                    ok = ct.CTkButton(master=dest_window,text="Ok",command=lambda: dest_window.destroy())
                                    ok.grid(row=3,column=0,padx=20,pady=10)             
                            dest_window = ct.CTk()
                            dest_window.geometry("500x250")
                            dest_window.grid_columnconfigure(0, weight=1)
                            dest_window.lift()
                            dest_window.title("Specify Destination")
                            # icon = tk.PhotoImage(file = os.path.join(image_path,"logo.png"))
                            # dest_window.iconphoto(False,icon)
                            dest_file_label = ct.CTkLabel(master=dest_window,text="Please specify the destination folder to save the report.")
                            dest_file_btn = ct.CTkButton(master=dest_window, text ='Browse', command= open_dest)
                            dest_file_label.grid(row=0,column=0,padx=20,pady=10)
                            dest_file_btn.grid(row=1,column=0,padx=20,pady=10)             
            def raw_to_audio(raw_file_path):
                try:
                    p_type = filtered_cap_rtp[0].rtp.p_type.showname
                    if (p_type.find('PCMU') != 1):
                        os.system(f"sox -t ul -r 8000 -c 1 {raw_file_path}.raw {raw_file_path}.wav")
                        click_to_save = ct.CTkButton(master=self.decode_to_audio_frame,text="Click to save",command=lambda: dest_window(raw_file_path))
                        click_to_save.grid(row=5,column=0,padx=20,pady=10)                        
                    elif (p_type.find('GSM') != 1):
                        os.system(f"sox -t gsm -r 8000 -c 1 {raw_file_path}.raw {raw_file_path}.wav")                   
                        click_to_save = ct.CTkButton(master=self.decode_to_audio_frame,text="Click to save",command=lambda: dest_window(raw_file_path))
                        click_to_save.grid(row=5,column=0,padx=20,pady=10)
                    elif (p_type.find('PCMA')!= 1):
                        os.system(f"sox -t al -r 8000 -c 1 {raw_file_path}.raw {raw_file_path}.wav") 
                        click_to_save = ct.CTkButton(master=self.decode_to_audio_frame,text="Click to save",command=lambda: dest_window(raw_file_path))
                        click_to_save.grid(row=5,column=0,padx=20,pady=10)
                    elif (p_type.find('G722')!= 1):
                        os.fsencode(f"{raw_file_path}.raw {raw_file_path}.wav")
                        click_to_save = ct.CTkButton(master=self.decode_to_audio_frame,text="Click to save",command=lambda: dest_window(raw_file_path))
                        click_to_save.grid(row=5,column=0,padx=20,pady=10)                        
                    elif (p_type.find('G729')!= 1):
                        os.fsencode(f"-l mod_com_g729 {raw_file_path}.raw {raw_file_path}.wav")
                        click_to_save = ct.CTkButton(master=self.decode_to_audio_frame,text="Click to save",command=lambda: dest_window(raw_file_path))
                        click_to_save.grid(row=5,column=0,padx=20,pady=10)
                    else:
                        tkmb.showerror(title="Codec unidentified",message="Something went wrong! Maybe invalid codec.")
                    
                except:
                    tkmb.showerror(title="Error",message="Something went wrong!")              
            def rtp_to_raw():
                rtp_list = []  
                raw_audio_path = f"cache_files/{token_hex(10)}"
                raw_audio = open(f"{raw_audio_path}.raw",'wb')
                for i in filtered_cap_rtp:
                    try:
                        rtp = i[3]
                        if rtp.payload:
                            rtp_list.append(rtp.payload.split(":"))
                    except:
                        pass
                for rtp_packet in rtp_list:
                    packet = " ".join(rtp_packet)
                    audio = bytearray.fromhex(packet)
                    raw_audio.write(audio)
                raw_to_audio(raw_audio_path)
            wait_message = ct.CTkLabel(master=self.decode_to_audio_frame,text="Please wait after opening the file...")
            wait_message.grid(row=3,column=0,padx=20,pady=10)
            filename = askopenfilename(title="Select the capture file",filetypes=[("Capture files", ".pcap .pcapng")])
            self.second_label.configure(text="File Opened: "+filename)
            wait_message.configure(text="File uploaded.")
            filtered_cap_rtp = pyshark.FileCapture(filename,display_filter='rtp')
            filtered_cap_rtp.load_packets()
            convert_button = ct.CTkButton(master=self.decode_to_audio_frame,text="Convert",command=rtp_to_raw)
            convert_button.grid(row=4,column=0,padx=20,pady=10)
        self.decode_to_audio_frame = ct.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.decode_to_audio_frame.grid_columnconfigure(0, weight=1)
        self.first_label = ct.CTkLabel(master=self.decode_to_audio_frame,text="Upload the PCAP file to decode to audio.")
        self.first_label.grid(row=0, column=0, padx=20, pady=10)
        self.second_label = ct.CTkLabel(master=self.decode_to_audio_frame,text="File Opened:")
        self.second_label.grid(row=1,column=0,padx=20,pady=10)
        self.file_open_button = ct.CTkButton(master=self.decode_to_audio_frame,text="Open",command=convert_to_audio)
        self.file_open_button.grid(row=2,column=0,padx=20,pady=10)
        

        def change_map(new_map: str):
            if new_map == "OpenStreetMap":
                self.map_widget.set_tile_server("https://a.tile.openstreetmap.org/{z}/{x}/{y}.png")
            elif new_map == "Google normal":
                self.map_widget.set_tile_server("https://mt0.google.com/vt/lyrs=m&hl=en&x={x}&y={y}&z={z}&s=Ga", max_zoom=22)
            elif new_map == "Google satellite":
                self.map_widget.set_tile_server("https://mt0.google.com/vt/lyrs=s&hl=en&x={x}&y={y}&z={z}&s=Ga", max_zoom=22)
        def search_event(event=None):
            def set_pos(la,lo):
                self.map_widget.set_position(la, lo)  # Paris, France
                self.map_widget.set_zoom(15)
            ip = self.entry.get()
            res = DbIpCity.get(ip, api_key="free")
            la,lo = res.latitude,res.longitude
            set_pos(la,lo) 
              
        self.geolocation_frame = ct.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.geolocation_frame.grid_columnconfigure(0, weight=1)
        self.map_widget = TkinterMapView(master=self.geolocation_frame, corner_radius=0,height=900)
        self.map_widget.grid(row=1,column=0,rowspan=6,columnspan=6, sticky="nswe", padx=(0, 0), pady=(0, 0))
        self.entry = ct.CTkEntry(master=self.geolocation_frame,
                                            placeholder_text="type IP")
        self.entry.grid(row=0, column=0, sticky="we", padx=(12, 0), pady=12)
        self.entry.bind("<Return>",search_event)
        self.map_option_menu = ct.CTkOptionMenu(self.geolocation_frame, values=["OpenStreetMap", "Google normal", "Google satellite"],
                                                                       command=change_map)
        self.map_option_menu.grid(row=0, column=5, padx=20, pady=10)        
        self.button_5 = ct.CTkButton(master=self.geolocation_frame,
                                                text="Search",
                                                width=90,
                                                command=search_event)
        self.button_5.grid(row=0, column=1, padx=20, pady=10)  
        self.map_widget.set_address("Chennai")
        self.map_option_menu.set("OpenStreetMap")      
    def select_frame_by_name(self, name):
        # set button color for selected button
        self.home_button.configure(fg_color=("gray75", "gray25") if name == "home" else "transparent")
        self.clear_cache_button.configure(fg_color=("gray75", "gray25") if name == "cache" else "transparent")
        self.password_change_button.configure(fg_color=("gray75", "gray25") if name == "password" else "transparent")
        self.decrypt_srtp_button.configure(fg_color=("gray75", "gray25") if name == "srtp" else "transparent")
        self.decode_to_audio_button.configure(fg_color=("gray75", "gray25") if name == "audio" else "transparent")
        self.geolocation_button.configure(fg_color=("gray75", "gray25") if name == "geoloc" else "transparent")
        # show selected frame
        if name == "home":
            self.home_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.home_frame.grid_forget()
        if name == "password":
            self.change_password_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.change_password_frame.grid_forget()
        if name == "cache":
            self.clear_cache_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.clear_cache_frame.grid_forget()
        if name == "srtp":
            self.decrypt_srtp_frame.grid(row=0, column=1, sticky="nsew")
        # else:
        #     self.decrypt_srtp_frame.grid_forget()
        if name == "audio":
            self.decode_to_audio_frame.grid(row=0, column=1, sticky="nsew")  
        # else:
        #     self.decode_to_audio_frame.grid_forget() 
        if name == "geoloc":
            self.geolocation_frame.grid(row=0, column=1, sticky="nsew")  
        # else:
        #     self.geolocation_frame.grid_forget()         
    def home_button_event(self):
        self.select_frame_by_name("home")

    def password_change_button_event(self):
        self.select_frame_by_name("password")

    def clear_cache_button_event(self):
        self.select_frame_by_name("cache")

    def decrypt_srtp_button_event(self):
        self.select_frame_by_name("srtp")

    def decode_to_audio_button_event(self):
        self.select_frame_by_name("audio")

    def geolocation_button_event(self):
        self.select_frame_by_name("geoloc")    

    def change_appearance_mode_event(self, new_appearance_mode):
        ct.set_appearance_mode(new_appearance_mode)


if __name__ == "__main__":
    login()