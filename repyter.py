import re
import requests

def burplike_header_string_input(message=None):
      inputed_s = []
      finished = False
      if message:
            print(message)
      while not finished:
            try:
                  inputed_str = input()
                  if inputed_str == '"'*3:
                        finished = True
                  if inputed_str and inputed_str != '"'*3:
                        inputed_s.append(inputed_str.strip())
            except:
                  break
      return inputed_s
def burplike_header_string_process(header_string=""):
      _METHOD = "GET"
      _HOST = ""
      _PATH = "/"
      _COOKIES = []
      _OTHERS = {}
      burp_header_string = burplike_header_string_input("Input your string, put 3 double quotes if done:\n\"\"\"")
      if burp_header_string:
            for header_line in burp_header_string:
                  # detecting the HTTP METHOD and PATH line
                  if re.match(r'[A-Z]+\ ', header_line):
                        _METHOD = re.match(r'([A-Z]+)\ ', header_line).group(1)
                        _PATH = re.match(r'[A-Z]+ (.*?) ', header_line).group(1)
                  # detecting cookie line
                  elif "cookie" in header_line.lower():
                        _COOKIES.append(header_line.lower().replace("cookie:","").strip())
                  # detecting host
                  elif "host" in header_line.lower():
                        _HOST = header_line.lower().replace("host:","").strip()
                  # detecting other headers
                  elif re.match(r'[a-zA-Z\-]+\:',header_line):
                        _hkey = header_line.lower().split(" ")[0].replace(":","")
                        _hval = " ".join(header_line.lower().split(" ")[1:])
                        _OTHERS[_hkey] = _hval
                  else:
                        pass
            _URL = "https://" + _HOST + _PATH
            _COOKIES = " ;".join(_COOKIES) if len(_COOKIES) > 1 else _COOKIES if _COOKIES else ""
            print(_URL, _COOKIES, _OTHERS)
                        
if __name__ == "__main__":
      burplike_header_string_process()