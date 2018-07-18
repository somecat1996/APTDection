#from scapy.all import *
import dpkt
import re
from fingerprints.LevenshteinDistance import *

class Fingerprint():
    """
    Object that describes a fingerprint of DECANTeR.
    """
    
    def __init__(self, label, ua, ip_dsts, const_head, lang, avg_size, outg_info, method_name, is_malicious=0):
        if label == "Background":
            self.label = label
            self.user_agent = ua
            # IP destinations added
            self.ip_dsts = ip_dsts
            self.constant_header_fields = const_head
            self.language = lang
            self.avg_size = float(avg_size)
            self.outgoing_info = int(outg_info)
            self.method = method_name
            # Label indicating whether request is malicious or benign
            # Used for analysis: 0 = benign, 1 = malicious.
            # Note - isMalicious is both added to __str__ and to_csv methods.
            self.is_malicious = is_malicious
        elif label == "Browser":
            self.label = label
            self.user_agent = ua
            self.language = lang
            self.method = method_name
            # IP destinations added - Added to __str__ as number of unique IP's as it becomes too large to print entirely
            self.ip_dsts = ip_dsts
            self.constant_header_fields = None
            self.avg_size = None
            self.outgoing_info = int(outg_info)
            # Label indicating whether request is malicious or benign
            # Used for analysis: 0 = benign, 1 = malicious.
            # Note - isMalicious is both added to __str__ and to_csv methods.
            self.is_malicious = is_malicious
        else:
            raise ValueError ('The label passed %s is not a "Browser" or "Background".' % (label)) 
            
    def __str__(self):
        if self.label == "Background":
            return """
            {} Application:
                    Method: {}
                    User-Agent: {}
                    Destination IP's: {}
                    Constant Headers: {}
                    Average Req Size: {}
                    Outgoing Info: {}
                    Is malicious: {}
            """.format(self.label, self.method, self.user_agent,  self.ip_dsts, self.constant_header_fields, self.avg_size, self.outgoing_info, self.is_malicious=='1')
        else:
            return """
            {} Application:
                    Method: {}
                    User-Agent: {}
                    destination IP's: {}
                    Language: {}
                    Outgoing Info: {}
                    Is malicious: {}
            """.format(self.label, self.method, self.user_agent, self.ip_dsts, self.language, self.outgoing_info, self.is_malicious=='1')
            
    '''
    def to_csv(self):
        if self.label == "Background":
            return [self.label, self.method, self.user_agent, self.hosts, self.ip_dsts, self.constant_header_fields, self.avg_size, self.outgoing_info, self.is_malicious]
        else:
            return [self.label, self.method, self.user_agent, self.hosts, self.ip_dsts, self.language, self.outgoing_info, self.is_malicious]
    '''

class FingerprintGenerator():
    """
    Object that is responsible of generating a fingerprint.
    """

    def __init__(self,filepath):
        self.counter_req = 0
        self.datapath = filepath
        pass

    def genrate(self,stream_groups):
        fingerprints={}
        app_requests=self.get_http_requests2(stream_groups)
        for key in app_requests:
            http_requests=app_requests[key]
            type=http_requests.pop()
            is_malicious=http_requests.pop()
            fingerprint=self.generate_fingerprint(http_requests,type,key,is_malicious)
            #stream_groups[key].append(fingerprint)
            fingerprints[key]=fingerprint
        return fingerprints
    
    def generate_fingerprint(self,http_requests,type_code,kinds,is_malicious):
        """
            Generate the fingerprint from a set of http requests sharing the same user-agent.
            
            This method takes as input a set of HTTP requests generated by an HTTP Application.
            It analyzes each HTTP request and it extracts the features needed to generate a fingerprint of
            that HTTP application.
            
            Finally, it generates and returns a fingerprint.
            
            Parameter
            ----------------
            method_cluster : list of HTTPRequest
                All HTTP requests belonging to the same application
                
            method_name : string
                Name of the method of HTTP requests (i.e., GET or POST)
                
            label : string
                Type of the HTTP request (i.e. Browser or Background)
                
            Returns
            ----------------
            finger : Fingerprint()
                Fingerprint of the cluster of HTTP requests
        """
        
        # Temporary variables needed for fingerprint generation

        cache = []
        total_size_headers = 0
        number_requests = len(http_requests)
        self.counter_req += len(http_requests)
        
        # Features for fingerprints
        #label = ""
        ip_dsts = kinds.split()[0]
        constant_header_fields = []
        average_size = 0.0
        user_agent = re.sub(ip_dsts+" ","",kinds)
        language = []
        outgoing_info = 0
        
        # Used for evasion analysis

        
        # Return None if there are no request to analyze. (i.e., fingerprint does not exist)
        if not http_requests:
            return None


        tmp_headers = {}
        method="GET"
        for http_request in http_requests:
            tmp = {}
            raw=http_request.split("\\r\\n")
            method=self.process_method(raw[0].split()[0])
            #tmp["method"]=method
            for x in raw:
                if len(x.split(": "))==2 and x.split(": ")[0]!="Cookie":
                    tmp[x.split(": ")[0]]=x.split(": ")[1]


            # Add languange
            if 'Accept-Language' in tmp:
                language.append(tmp['Accept-Language'])
       
            uri=self.GetUri(http_request)
            uri_length = len(uri)
            tmp["uri"]=uri

            # Case 1 : First HTTP Request
            if not cache:
                # Add first request to the cache
                cache.append(tmp)
                
                # Update the total size of the header with the size of each part of the HTTP request
                total_size_headers += uri_length
                for header_name in tmp:
                    total_size_headers += len(header_name)
                    total_size_headers += len(tmp[header_name])
                    tmp_headers[header_name] = 1

                outgoing_info = total_size_headers
                if "Content-Length" in tmp:
                    outgoing_info+=int(tmp["Content-Length"])
                # Update outgoing information

      
            # Case 2 : non-First HTTP Request
            else:
                
                # Update outgoing information
                outgoing_info = self._compute_outgoing_info(tmp, cache[0], outgoing_info, cache)
                
                # Update the total size of the header with the size of each part of the HTTP request
                total_size_headers += uri_length
                for header_name in tmp:
                    total_size_headers += len(header_name)
                    total_size_headers += len(tmp[header_name])
                    if header_name not in tmp_headers:
                        tmp_headers[header_name] = 1
                    else:
                        tmp_headers[header_name] += 1
                        
        
        # Set Constant Header Fields
        for key in tmp_headers:
            val=tmp_headers[key]
            if val == number_requests:
                constant_header_fields.append(key)
                
        # Set Average Size
        average_size = total_size_headers / float(number_requests)

        if type_code==1 or type_code==3:
            label="Browser"
        else:
            label="Background"

        if not language:
            lang="none"
        else:
            lang=language[0]
        # Generate Fingerprint for the given cluster of HTTP requests
        finger = Fingerprint(label, user_agent,ip_dsts, constant_header_fields, lang, average_size,
                             outgoing_info, method, is_malicious)
        
        return finger
        

    def get_http_requests(self,stream_groups):
        app_requests={}
        ptr=".*(GET|POST).*HTTP.*"
        for key in stream_groups:
            requests = []
            is_malicious=0
            for x in stream_groups[key]:
                if x["is_malicious"]!=0:
                    is_malicious=1
                filename=self.datapath+'/'+x["filename"]
                #source=PcapReader(filename)
                f = open(filename, "rb")
                source = dpkt.pcap.Reader(f)
                packet = dpkt_next(source)
                #packet=source.read_packet()
                while packet:
                    s=packet_to_str(packet)
                    if re.match(ptr, s):
                        requests.append(s)
                    packet = dpkt_next(source)
            requests.append(is_malicious)
            requests.append(stream_groups[key][0]["type"])
            #print(requests)
            app_requests[key]=list(requests)
        return app_requests

    def get_http_requests2(self,stream_groups):
        app_requests={}
        ptr=".*(GET|POST).*HTTP.*"
        for key in stream_groups:
            requests = []
            is_malicious=0
            for x in stream_groups[key]:
                if x["is_malicious"]!=0:
                    is_malicious=1
                '''
                filename=self.datapath+'/'+x["filename"]
                #source=PcapReader(filename)
                f = open(filename, "rb")
                source = dpkt.pcap.Reader(f)
                packet = dpkt_next(source)
                #packet=source.read_packet()
                while packet:
                    s=packet_to_str(packet)
                    if re.match(ptr, s):
                        requests.append(s)
                    packet = dpkt_next(source)
              '''
                for y in x["http"]:
                    requests.append(str(y))
            requests.append(is_malicious)
            requests.append(stream_groups[key][0]["type"])
            #print(requests)
            app_requests[key]=list(requests)
        return app_requests

    def GetUri(self,http_request):
        pattern1 = "/.*?HTTP"
        pattern2 = "/.*?\\?"
        pattern3 = "Host.*?\\\\r"

        ttt = re.findall(pattern1, http_request)[0]
        if not re.findall(pattern2, ttt):
            ttt = ttt.strip(" HTTP")
        else:
            ttt = re.findall(pattern2, ttt)[0].strip("?")
        try:
            uri = re.findall(pattern3, http_request)[0].strip("\\r").strip("Host: ") + ttt
        except:
            uri="none"
            return uri
        uri_tmp = re.sub("http://", "", uri)

        return uri_tmp

    def _compute_outgoing_info(self, current_req, old_req, outgoing_info, cache):
        """
            Compute Outgoing information and update the cache.
            
            This method computes the outgoing information by comparing the current HTTP request with the
            previously analyzed HTTP request. Once the comparison is finished, the old request is removed
            from the cache, and the current request is added in the cache.
            
            Parameter
            ------------
            current_req : HTTPRequest
                HTTPRequest we are currently analyzing
            
            old_req : HTTPRequest
                HTTPRequest previously analyzed
                
            outgoing_info : int
                Current value of outgoing information
                
            cache : list of HTTPRequest
                List containing the previous HTTPRequest (i.e., old_req)
                
            Return
            ------------
            outgoing_info : int
                Update outgoing information value
        """
        # Approximation of size for POST for efficiency reasons.
        if "Content-Length" in current_req:
            outgoing_info+=int(current_req["Content-Length"])
        
        outgoing_info += self._levenshtein_distance(current_req["uri"], old_req["uri"])
        
        # Compute Outgoing information for each header name in the request
        for header_name in current_req:
            if header_name not in old_req:
                outgoing_info += len(current_req[header_name])
            else:
                outgoing_info += self._levenshtein_distance(current_req[header_name],
                                                      old_req[header_name] )
        
        # Update cache
        cache.pop()
        cache.append(current_req)
        return outgoing_info
    
    
    def process_method(self,method):
        method_list=["GET","POST","HEAD","OPTIONS","DELETE","PUT","CONNECT","TRACE"]
        for x in method_list:
            if x in method:
                return x
        return method


    def _levenshtein_distance(self, s1, s2):
        """ Compute the Levenshtein distance.
            
            Parameter
            -----------
            s1, s2 : string
                Two strings to compare
                
            Result
            -----------
            distances[-1] : int
                (Levenshtein) Edit distance
            
            """
        
        return LevenshteinDistance(s1,s2)


class FingerprintManager():
    """
    Object used to loads/load fingerprints from/to files or to store them temporarily in a dictionary.
    """
    def __init__(self):
        self.fingerprints = {}
        
    
    def store(self, fingerprint_group):
        if fingerprint_group is None:
            pass
        else:
            for x in fingerprint_group:
                self.fingerprints[x] = fingerprint_group[x]

    
    
    def get_fingerprint(self, kinds):
        return self.fingerprints[kinds]
    
    
    def __str__(self):
        for key in self.fingerprints:
            fingerprint=self.fingerprints[key]
            print("kinds: " + key)
            print(fingerprint)

def dpkt_next(reader):
    try:
        p=next(reader)
        return p
    except:
        return None

def packet_to_str(packet):
    try:
        p = dpkt.ethernet.Ethernet(packet[1])
        s = str(p.data.data.pack()[p.data.data.__hdr_len__:])
    except:
        return "notvalid"  
    return s
    

