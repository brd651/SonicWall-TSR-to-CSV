import re
import os

class TSR_data_format(object):
    def __init__(self, tsr):
        self.tsr = tsr
    def tsr_processing(self):
        # tested with 6.5.4.3-28n TSR
        f = {}
        i = 0
        stop = False
        with open(self.tsr, "r", encoding="cp1252", errors="replace") as input_data:
            lines = input_data.readlines()
            while i < len(lines):
                end = True
                # creating list and emptying the list each time this is looped
                e = []
                # this regex is going through the TSR and looking for a # at the begining of the line then 1 whitespace before a :
                # this is to prevent any possible issues throughout the rest of the TSR
                if re.search(r'^#.*\s:', lines[i]):
                    # here we are declaring 2 Variables to get the Section and the Subsection to be defined as keys in the dictionary
                    outkey = re.search(r'(?:^#)(.*)(?:\s:)', lines[i])[1]
                    innerkey = re.search(r'(?::\s)(.*)(?:_)', lines[i])[1]
                    # checking to see if the key exists or not, and adding an empty list value to the inner key/Subsection
                    if outkey in f.keys():
                        f[outkey].update({innerkey: {}})
                    else:
                        f.update({outkey : {innerkey: {}}})
                    end = False
                    i+=1
                    # this is here to define the appending of each line in the TSR to a list, once the _END is found in a line
                    # the end variable gets assigned True thous adding that list to the SubSection in the Multi-dimensional Dictionary
                    # and then starting the loop over again
                    # print(f'{outkey}  {innerkey}')
                    while end is False:
                        # if re.search(r'^#.*\s:.*_END', lines[i]):
                        if "_END" in lines[i]:
                            f[outkey][innerkey] = e
                            i += 1
                            if "#Diagnostic " in lines[i-1]:
                                print("End it")
                                stop = True
                            end = True
                        # this is looking for the sub topic to break down the sections even further for easier pulling of info
                        elif re.search(r'^--(\w.*)--\n', lines[i]):
                            subinnerkey = re.search(r'^--(\w.*)--\n', lines[i])[1]
                            i += 1
                            sub = True
                            s = []
                            while sub is True:
                                if re.search(r'^--(\w.*)--\n', lines[i]):
                                    f[outkey][innerkey][subinnerkey] = s
                                    i -= 1
                                    sub = False
                                # elif re.search(r'^#.*\s:.*_END', lines[i]):
                                elif "_END" in lines[i]:
                                    f[outkey][innerkey][subinnerkey] = s
                                    sub = False
                                    end = True
                                    if "#Diagnostic " in lines[i]:
                                        stop = True
                                # elif re.search(r'^\n', lines[i]):
                                elif len(lines[i]) == 1:
                                    i += 1
                                    continue
                                else:
                                    s.append(lines[i].strip())
                                    i += 1
                        # elif re.search(r'^\n', lines[i]):
                        elif len(lines[i]) == 1:
                            i += 1
                            continue
                        else:
                            e.append(lines[i].strip())
                        i += 1
                elif stop is True:
                    break
                else:
                    i += 1
        return(f)


class processors(object):
    def __init__(self, TSR):
        self.TSR = TSR
        self.data = {}

    def cleaner(self):
    # def SystemInfo_processing(self):
        SystemInfo = {}
        for si in self.TSR['System']['Status']['System Information']:
            if "Internal Instanc" not in si:
                SystemInfo[si.split(":", 1)[0].strip()] = si.split(":", 1)[1].strip()
        self.data['SystemInfo'] = SystemInfo

    # def Access_Rule_processing(self):
        Access_Rules_Dirty = self.TSR["Firewall"]["Access Rules"]

        Access_Rules = {}
        
        for AR in Access_Rules_Dirty:
            if "Rule " in AR:
                rule = re.search(r'(?:Rule\s)'
                                r'(?P<rule>.+?)\s'
                                r'(?P<zone_src>[\W\w\s]*?)\s->\s'
                                r'(?P<zone_dst>[\W\w\s]*?)\s'
                                r'(?P<action>Deny|Discard|Allow)\s\w+\s'
                                r'(?P<svc_src>[\W\w\s]*?)\s.*?\s'
                                r'(?P<svc_dst>[\W\w\s]*?)\s'
                                r'\((?P<enabled>\w+)\)', AR)
                rules = rule.groupdict()
                rule_num = rules['rule']
                rules.pop('rule')
                Access_Rules[rule_num] = dict(rules)
            elif re.match(r'(Time\s|Usage\s|Instance\:|UUID\:|Policy\s|Bytes\,'
                        r'|Global\s|Current\s|Save\s|Maximum\s|Dynamic\s)', AR):
                # there are just a bunch of extra things that I am currently not utilizing so we will just bypass them for now
                continue
            elif "IP: " in AR:
                IP = re.search(r'^(?:IP:.+?)(.*?)\-\>(.*?)(?:Iface:)', AR)
                Access_Rules[rule_num]["ip_src"] = IP.group(1)
                Access_Rules[rule_num]["ip_dst"] = IP.group(2)
            else:
                line, line2 = AR.split(":", 1)
                if re.search(r'(Management:|(Packet Monitor:))', line2):
                    options = line2.split(":")
                    if "Packet Monitor" in options[0]:
                        options[0] = "Packet Monitor"
                        Access_Rules[rule_num][options[0]] = options[1]
                    elif "Management" in options[0]:
                        options[0] = "Management"
                        Access_Rules[rule_num][options[0]] = options[1]
                elif re.search(r'(Included:|TCP:)', line2):
                    options = re.split(r'(?:\s\s)([\w\s]+)\:([\w\s]+)', line2)
                    if "TCP" in options[1]:
                        Access_Rules[rule_num][options[1].strip() + " Connection Inactivity Timeout"] = options[2]
                        Access_Rules[rule_num][options[4] + " Connection Inactivity Timeout"] = options[5]
                    else:
                        Access_Rules[rule_num][options[1].strip()] = options[2]
                        Access_Rules[rule_num][options[4]] = options[5]
                else:
                    Access_Rules[rule_num][line] = line2.strip()
        self.data['Access Rules'] = Access_Rules

    # #def Address_obj_processing():
        Addresss_obj_Dirty = self.TSR["Network"]['Address Objects']["Address Object Table"]

        Address_objs = {}

        for addr in Addresss_obj_Dirty:
            if re.search(r'^-', addr):
                if re.search(r'-{42}', addr):
                    break
                else:
                    addr_name = addr[7:-7]
                    Address_objs[addr_name] = {}
            elif re.search(r'(^UUID|^Time Created|referenced by)', addr):
                # excluding UUID and Time created and updated for now till I need them and referenced by not linkable directly
                continue
            elif re.search(r'(^HOST:|^Class|properties|FQDN:|Manually Set TTL|NETWORK:|HOST\(S\):|Group \(Member of\):|Range:|MAC:)', addr):
                Address_objs[addr_name][addr.split(":", 1)[0]] = addr.split(":", 1)[1].strip()
            else:
                # there is a lot of junk in this dictionary that I am currently not using so skip it
                continue
        self.data['Address Objects'] = Address_objs

    ##def Address_grp_processing():
        Addresss_grp_Dirty = self.TSR["Network"]['Address Objects']["Address Group Table"]

        Address_grps = {}

        for addr in Addresss_grp_Dirty:
            if re.search(r'^-', addr):
                addr_name = addr[7:-7]
                Address_grps[addr_name] = {}
            elif re.search(r'(^UUID|^Time Created|referenced by)', addr):
                # excluding UUID and Time created and updated for now till I need them and referenced by not linkable directly
                continue
            elif re.search(r'(^HOST:|^Class|properties|Group \(Member of\):)', addr):
                Address_grps[addr_name][addr.split(":")[0]] = addr.split(":")[1].strip()
        self.data['Address Groups'] = Address_grps

    ##def Service_obj_processing():
        Service_obj_Dirty = self.TSR["Network"]["Services"]["Service Object Table"]

        Service_objs = {}
        prop_dict = {"0x00002e1d": "Mgmt Default","0x0000000e": "Custom", "0x00012c1d": "ICMP Default", "0x00002c1d" : "Default"}

        for svc in Service_obj_Dirty:
            if re.search(r'^-', svc):
                svc_name = svc[7:-7]
                Service_objs[svc_name] = {}
            elif re.search(r'(^UUID|^Time Created)', svc):
                #excluding UUID and Time created and updated for now till I need them
                continue
            elif "properties" in svc:
                prop_value = prop_dict[svc.split(":")[1].strip()]
                Service_objs[svc_name]["properties"] = prop_value
            elif "IpType" in svc:
                if "IcmpType" in svc:
                    iptype, icmptype, icmpcode = ["I"+e.strip() for e in svc.split("I") if e]
                    Service_objs[svc_name][iptype.split(":")[0]] = iptype.split(":")[1].replace(",", "")
                    Service_objs[svc_name][icmptype.split(":")[0]] = icmptype.split(":")[1]
                    Service_objs[svc_name][icmpcode.split(":")[0]] = icmpcode.split(":")[1]
                else:
                    iptype, port = svc.split(",")
                    Service_objs[svc_name][iptype.split(":")[0]] = iptype.split(":")[1].strip()
                    Service_objs[svc_name][port.split(":")[0].strip()] = iptype.split(":")[1].replace("~", "-").strip()
            elif "Group" in svc:
                # excluding the handle option there till I know what it does
                Service_objs[svc_name][svc.split(":")[0].strip()] = svc.split(":")[1].strip()
        self.data['Service Objects'] = Service_objs

    #def Service_grp_processing():
        Service_grp_Dirty = self.TSR["Network"]["Services"]["Service Group Table"]

        Service_grps = {}

        for svc in Service_grp_Dirty:
            if re.search(r'^-', svc):
                try:
                    Service_grps[svc_name]["members"] = members
                except UnboundLocalError:
                    pass
                members = []
                svc_name = svc[7:-7].split("(")[0]
                Service_grps[svc_name] = {}
            elif "UUID:" in svc:
                continue
            elif "properties:" in svc:
                prop_value = prop_dict[svc.split(":")[1].strip()]
                Service_grps[svc_name]["properties"] = prop_value
            elif "member:" in svc:
                members.append(svc.split(":")[2][:-7])
            elif "Group" in svc:
                Service_grps[svc_name][svc.split(":")[0].strip()] = svc.split(":")[1].strip()
        self.data['Service Groups'] = Service_grps

    #def Zones_processing():
        zones_Dirty = self.TSR["Network"]["Zones"]["Zone Object Table"]

        zones = {}

        start = False
        for z in zones_Dirty:
            if start is True:
                if re.search(r'^-+\s(\w)+', z):
                    zone_name = z[22:-22].split("(")[0]
                    zones[zone_name] = {}
                elif re.search(r'(^UUID|^Time Created|^--------------|^Guest Services|^General Settings|'
                            r'^Wireless Settings|^Radius Server Settings)', z):
                    continue
                else:
                    zones[zone_name][z.split(":")[0]] = z.split(":")[1].strip()
            else:
                if re.search(r'^-+\s\w+', z):
                    start = True
                    zone_name = z[22:-22].split("(")[0]
                    zones[zone_name] = {}
                else:
                    start = False
        self.data['Zones'] = zones

    #def Interface_processing():
        interfaces_Dirty = self.TSR['Network']['Interfaces']

        interfaces = {}

        skip = ""
        for index, i in enumerate(interfaces_Dirty):
            if "Interface Name" in i or re.search(r'Interface\s{23}:', i):
                IP_Version = ""
                if "Interface Name" in i:
                    Interface = i.split(":", 1)[1].strip()
                    interfaces[i.split(":", 1)[1].strip()] = {}
                else:
                    Interface = i.split(":", 1)[1].strip().replace("                               ", " ")
                    interfaces[Interface] = {}
            elif skip == index:
                continue
            elif "[IPv4 Settings]" in i:
                IP_Version = i.replace("[", "").replace("]", "")
                interfaces[Interface][IP_Version] = {}
            elif "[IPv6 Settings]" in i:
                IP_Version = i.replace("[", "").replace("]", "")
                interfaces[Interface][IP_Version] = {}
            elif "ENET_" in i:
                interfaces[Interface]["Link Ability"] = [interfaces[Interface]["Link Ability"]].append(i)
            elif "IPv6 Addresses" in i:
                skip = index + 1
                interfaces[Interface][IP_Version][i] = interfaces_Dirty[index + 1]
            elif "Interface Traffic Statistics" in i:
                break
            elif "No Prefix Configured" in i:
                continue
            elif re.search(r'-{65}', i):
                continue
            else:
                if IP_Version:
                    interfaces[Interface][IP_Version][i.split(":")[0].strip()] = i.split(":")[1].strip()
                else:
                    interfaces[Interface][i.split(":", 1)[0].strip()] = i.split(":", 1)[1].strip()
        self.data['Interfaces'] = interfaces

    #def NAT_Rule_processing():
        NAT_Rule_Dirty = self.TSR["Network"]["NAT Policies"]

        NAT_Rules = {}

        for n in NAT_Rule_Dirty:
            if "IP Version" in n:
                IP_Version = n.split(":")[1].strip()
                continue
            elif "Index" in n:
                index = n.split(":")[1].strip()
                try:
                    NAT_Rules[IP_Version][index] = {}
                except KeyError:
                    NAT_Rules[IP_Version] = {}
                    NAT_Rules[IP_Version][index] = {}
            elif re.search(r'^-', n):
                continue
            elif "Port Remap Hash:" in n:
                break
            else:
                NAT_Rules[IP_Version][index][n.split(":")[0].strip()] = n.split(":")[1].strip()
        self.data['NAT Rules'] = NAT_Rules

    #def Route_Policy_processing():
        Route_Dirty = self.TSR["Network"]["Routing"]["Route Policies"]

        Routes = {}

        i4 = 0
        i6 = 0
        for ro in Route_Dirty:
            if "Internal IPv" in ro:
                IP_Version = ro.split(" ")[1]
                Routes[IP_Version] = {}
            elif "Handle"  in ro:
                headers = re.findall(r'([\w|/|-]+)', ro)
            elif "Idx" in ro:
                headers = re.findall(r'([\w|/|-]+)', ro)
            elif re.search(r'^\d', ro) and IP_Version == "IPv4":
                Routes[IP_Version][i4] = {}
                values = re.search(r'(.{11})(.{7})(.{20})(.{20})(.{20})(.{20})(.{14})(.{16})(.{20})(.{7})(.{9})(.*)', ro)
                for index, v in enumerate(values.groups()):
                    Routes[IP_Version][i4][headers[index]] = v.strip()
                i4 += 1
            elif re.search(r'^\d', ro) and IP_Version == "IPv6":
                Routes[IP_Version][i6] = {}
                values = re.search(r'(.{11})(.{4})(.{4})(.{44})(.{44})(.{44})(.{20})(.{14})(.{40})(.{19})(.{7})(.{9})(.*)', ro)
                for index, v in enumerate(values.groups()):
                    Routes[IP_Version][i6][headers[index]] = v.strip()
                i6 += 1
            elif "No-Atom Route" in ro:
                break
        self.data['Routes'] = Routes

    #def IDP_processing():
        IPS_Cats = self.TSR["Security Services"]["Intrusion Prevention"]["IPS Categories"]
        IPS_Excl = self.TSR["Security Services"]["Intrusion Prevention"]["IPS Exclusion List"]
        IPS_Global = self.TSR["Security Services"]["Intrusion Prevention"]["IPS Global Settings"]

        IPS = {}

        for i in IPS_Cats:
            if "Category" in i:
                category_name = i.split(":")[1].strip()
                try:
                    IPS["Category"][category_name] = {}
                except KeyError:
                    IPS["Category"] = {}
                    IPS["Category"][category_name] = {}
            elif re.search(r'(Schedule|Log Redundancy)', i):
                IPS["Category"][category_name][i.split(":")[0].strip()] = i.split(":")[1].strip()
            else:
                value = re.search(r'^(.*)(?::\s+?)(.*)(?:\s\s+)(.*)(?::\s+?)(.*)', i)
                IPS["Category"][category_name][value.group(1).strip()] = value.group(2).strip()
                IPS["Category"][category_name][value.group(3).strip()] = value.group(4).strip()

        IPS["Global Settings"] = {}
        for i in IPS_Global:
            IPS["Global Settings"][i.split(":")[0].strip()] = i.split(":")[1].strip()

        IPS["Exclusion List"] = {}
        for i in IPS_Excl:
            IPS["Exclusion List"][i.split(":")[0].strip()] = i.split(":")[1].strip()
        self.data['Intrusion Prevention'] = IPS

    #def GAV_processing():
        GAV_Dirty  =    self.TSR["Security Services"]["Gateway Anti-Virus"]["Gateway Anti-Virus Global Settings"]
        GAV_Dirty2 =   (self.TSR["Security Services"]["Gateway Anti-Virus"]["Gateway AV Settings"] +
                        self.TSR["Security Services"]["Gateway Anti-Virus"]["Gateway AV Exclusion List"] +
                        self.TSR["Security Services"]["Gateway Anti-Virus"]["Cloud Anti-Virus"])
        GAV = {}

        for g in GAV_Dirty:
            if re.search(r'([\w]+)\s([\w]+ Inspection)', g):
                proto = re.search(r'([\w]+)\s([\w]+ Inspection)', g).group(1)
                in_or_out = re.search(r'([\w]+)\s([\w]+ Inspection)', g).group(2)
                e_o_d = g.split(":")[1].strip()
                try:
                    GAV[proto][in_or_out] = e_o_d
                except KeyError:
                    GAV[proto] = {}
                    GAV[proto][in_or_out] = e_o_d
            elif "Restrict" in g:
                GAV[proto][g.split(":")[0]] = g.split(":")[1].strip()
        for g in GAV_Dirty2:
            GAV[g.split(":")[0].strip()] = g.split(":")[1].strip()
        self.data['Gateway Anti-Virus'] = GAV

    #def CATP_processing():
        CATP_Dirty = self.TSR["Security Services"]["Gateway Anti-Virus"]["Capture ATP"]
        CATP_AO_Exclusions = self.TSR["Security Services"]["Gateway Anti-Virus"]["Capture ATP Address Object Exclusion List"]
        CATP_BUV_Excluions = self.TSR["Security Services"]["Gateway Anti-Virus"]["Capture ATP Block Until Verdict Address Object Exclusion List"]
        CATP_BUV_File_Types = self.TSR["Security Services"]["Gateway Anti-Virus"]["Capture ATP Block Until Verdict file type exclusions"]
        CATP_FQDN_Exclusions = self.TSR["Security Services"]["Gateway Anti-Virus"]["Capture ATP FQDN Exclusion List"]

        CATP = {}

        for cat in CATP_Dirty:
            if ":" in cat:
                CATP[cat.split(":")[0].strip()] = cat.split(":")[1].replace(".","").strip()

        CATP["Address Object Exclusion List"] = {}
        for cat in CATP_AO_Exclusions:
            if re.search(r'^Address', cat):
                CATP["Address Object Exclusion List"][cat.split(" is ")[0]] = cat.split(" is ")[1]
            else:
                CATP["Address Object Exclusion List"][cat.split(":")[0]] = cat.split(":")[1]

        CATP["Block Until Verdict Address Object Exclusion List"] = {}
        for cat in CATP_AO_Exclusions:
            if re.search(r'^Address', cat):
                CATP["Block Until Verdict Address Object Exclusion List"][cat.split(" is ")[0]] = cat.split(" is ")[1]
            else:
                CATP["Block Until Verdict Address Object Exclusion List"][cat.split(":")[0]] = cat.split(":")[1]

        CATP["Block Until Verdict file type exclusions"] = {}
        for cat in CATP_BUV_File_Types:
            CATP[cat.split(":")[0].strip()] = cat.split(":")[1].replace(".","").strip()

        CATP["FQDN Exclusion List"] = {}
        skip = ""
        for index, cat in enumerate(CATP_FQDN_Exclusions):
            if index == skip:
                continue
            elif "FQDN" in cat:
                if "Capture Status Link" in CATP_FQDN_Exclusions[index+1]:
                    CATP["FQDN Exclusion List"][cat.split(":")[0]] = "none"
                else:
                    CATP["FQDN Exclusion List"][cat.split(":")[0]] = [CATP_FQDN_Exclusions[index+1].replace("^", ",")]
            elif "Rules in sbox cache" in cat:
                break
        self.data['Capture ATP'] = CATP

    #def Spy_processing():
        Spy_Dirty = (self.TSR["Security Services"]["Anti-Spyware"]["Anti-Spyware Exclusion List"] +
                    self.TSR["Security Services"]["Anti-Spyware"]["Anti-Spyware Global Settings"] +
                    self.TSR["Security Services"]["Anti-Spyware"]["Anti-Spyware Settings"] +
                    self.TSR["Security Services"]["Anti-Spyware"]["Anti-Spyware Status"] +
                    self.TSR["Security Services"]["Anti-Spyware"]["HTTP Clientless Notification"])

        Anti_Spyware = {}

        for spy in Spy_Dirty:
            Anti_Spyware[spy.split(":", 1)[0].strip()] = spy.split(":", 1)[1].strip()
        self.data['Anti-Spyware'] = Anti_Spyware

    #def DPI_SSL_processing():
        DPI_SSL_CNE_Dirty  = self.TSR["DPI-SSL"]["Client SSL"]["Common Name Exclusions"]
        DPI_SSL_Gen_Dirty  = self.TSR["DPI-SSL"]["Client SSL"]["General Settings"]
        DPI_SSL_InEx_Dirty = self.TSR["DPI-SSL"]["Client SSL"]["Inclusion/Exclusion"]

        DPI_SSL = {}

        DPI_SSL["Common Name Exclusions"] = {}
        for cne in DPI_SSL_CNE_Dirty:
            if "Default Exclusions" in cne:
                DPI_SSL["Common Name Exclusions"][cne.split(":")[0].strip()] = [cne.split(":")[1].replace("^", ",")]
            elif "Exclusions" in cne:
                DPI_SSL["Common Name Exclusions"][cne.split(":")[0].strip()] = [cne.split(":")[1].replace("^", ",")]
            elif "Skip Auth" in cne:
                DPI_SSL["Common Name Exclusions"][cne.split(":")[0].strip()] = [cne.split(":")[1].replace("^", ",")]
            elif "Override CFS Category CName list" in cne:
                DPI_SSL["Common Name Exclusions"][cne.split(":")[0].strip()] = [cne.split(":")[1].replace("^", ",")]
            elif "Skip authenticating the server" in cne:
                DPI_SSL["Common Name Exclusions"][cne.split(":")[0].strip()] = [cne.split(":")[1].replace("^", ",")]
            elif "CName Approved" in cne:
                DPI_SSL["Common Name Exclusions"][cne.split(":")[0].strip()] = [cne.split(":")[1].replace("^", ",")]
            elif "CName Rejected" in cne:
                DPI_SSL["Common Name Exclusions"][cne.split(":")[0].strip()] = [cne.split(":")[1].replace("^", ",")]
            elif "CName run time exclusions" in cne:
                break

        for gen in DPI_SSL_Gen_Dirty:
            DPI_SSL[gen.split(":")[0].strip()] = gen.split(":")[1].strip()

        for inex in DPI_SSL_InEx_Dirty:
            if "CFS Category based exclusion mask" in inex:
                data = re.search(r'(CFS Category based exclusion mask).*(\[.*\])', inex)
                DPI_SSL[data.group(1)] = data.group(2)
            elif "CFS Category based exclusion mode" in inex:
                data = re.search(r'(CFS Category based exclusion mode):(\d)\s(Exclusion when no CFS):(\d)', inex)
                DPI_SSL[data.group(1)] = data.group(2)
                DPI_SSL[data.group(3)] = data.group(4)
            elif re.search(r'^SSL', inex):
                continue
            else:
                DPI_SSL[inex.split(":")[0].strip()] = inex.split(":")[1].strip()
        self.data['DPI-SSL'] = DPI_SSL

    #def App_Rules_processing():
        App_Rules_Dirty = self.TSR['Firewall']['Application Firewall']['App Rules']

        App_Rules = {}
        App_Rules["Policies"] = {}

        for ap in App_Rules_Dirty:
            if re.search(r"^App Rules", ap) or re.search(r"^Global Log", ap):
                App_Rules[ap.split(":")[0].strip()] = ap.split(":")[1].strip()
            elif "Policies" in ap:
                continue
            elif re.search(r'^Rule', ap):
                ru = re.search(r'^Rule\s([\d]+)\s+:\s(.*)(?:\s-\s)([\w]+)', ap)
                rule_num = ru.group(1)
                if ru.group(3) == "Enabled":
                    EoD = 1
                else:
                    EoD = 0
                App_Rules["Policies"][rule_num]= {}
                App_Rules["Policies"][rule_num]["Name"] = ru.group(2)
                App_Rules["Policies"][rule_num]["Enabled"] = EoD
            elif re.search(r'^\(Source\)', ap) or re.search(r'^\(Destination\)', ap):
                src_dst = re.search(r'^(.{21}):(.*?),(.{10}):(.*?);(.{29}):(.*?),(.{12}):(.*?),(.{15}):(.*)', ap)
                App_Rules["Policies"][rule_num][src_dst.group(1).strip()] = src_dst.group(2).strip()
                App_Rules["Policies"][rule_num][src_dst.group(3).strip()] = src_dst.group(4).strip()
                App_Rules["Policies"][rule_num][src_dst.group(5).strip()] = src_dst.group(6).strip()
                App_Rules["Policies"][rule_num][src_dst.group(7).strip()] = src_dst.group(8).strip()
                App_Rules["Policies"][rule_num][src_dst.group(9).strip()] = src_dst.group(10).strip()
            elif "Logging" or "Match" in ap:
                for a in ap.split(","):
                    if re.search(r'Exclusion Address', a) or re.search(r'Enable Logging',a):
                        App_Rules["Policies"][rule_num][a.split(":")[0]] = a.split(":")[1]
                    else:
                        App_Rules["Policies"][rule_num][a.split(":")[0][1:]] = a.split(":")[1]
        self.data['App Rules'] = App_Rules

    #def Match_obj_processing():

    #def Action_obj_processing():

    #def App_Control_processing():
        App_Con_Adv_Dirty = self.TSR['Firewall']['Application Firewall']['App Control Advanced']
        App_Con_Cats_Dirty = self.TSR['Firewall']['Application Firewall']['App Control Categories']

        App_Con = {}

        for a in App_Con_Adv_Dirty:
            if "Enable App" in a:
                App_Con[a.split(":")[0].strip()] = a.split(":")[1].strip()
            elif " Exclusion List is" in a:
                App_Con[a.split("is using")[0].strip()] = a.split("is using")[1].strip()

        for a in App_Con_Cats_Dirty:
            if "Category" in a:
                cat = a.split(":")[1].strip()
                try:
                    App_Con["Category"][cat] = {}
                except KeyError:
                    App_Con["Category"] = {}
                    App_Con["Category"][cat] = {}
            elif re.search(r'(Schedule|Log Redundancy)', a):
                App_Con["Category"][cat][a.split(":")[0].strip()] = a.split(":")[1].strip()
            else:
                value = re.search(r'^(.*)(?::\s+?)(.*)(?:\s\s+)(.*)(?::\s+?)(.*)', a)
                App_Con["Category"][cat][value.group(1).strip()] = value.group(2).strip()
                App_Con["Category"][cat][value.group(3).strip()] = value.group(4).strip()
        self.data['App Control'] = App_Con

    #def SSL_VPN_processing():

    #def VPN_processing():

    #def SDWAN_processing():

    #def Access_points_processing():

    #def Firewall_Settings_processing():
        Firewall_Settings_dirty = self.TSR['Firewall Settings']['Advanced']['Advanced']

    #def Flood_Protection_processing():
        Flood_Protection_dirty = self.TSR['Firewall Settings']['Advanced']['Flood Protection']

    #def High_Availability_processing():
        HA_Advanced_dirty = self.TSR['High Availability']['Advanced']
        HA_Monitoring_dirty = self.TSR['High Availability']['Monitoring']
        HA_Settings_dirty = self.TSR['High Availability']['Settings']

# DataInput = TSR_data_format(file)
# DataProcess = processors(DataInput.tsr_processing())

# DataProcess.cleaner()

# print(DataProcess.data.keys())
