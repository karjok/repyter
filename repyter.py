import re
import os
import sys
import json
import requests
from prompt_toolkit import prompt
from urllib.parse import unquote_plus


# colors
cyan = "\033[96m"
reset = "\033[0m"

_requester = requests.Session()

def burplike_header_string_input(message=None):
      if message:
            os.system("clear")
            terminal_size = os.get_terminal_size().columns
            print(f"{cyan}░{reset}" * terminal_size)
            for message_text in message.split("\n"):
                  total_padding = terminal_size - len(message_text)
                  left_padding = total_padding // 2
                  right_padding = total_padding - left_padding
                  print(f"{cyan}{'░' * left_padding}{reset}{message_text}{cyan}{'░' * right_padding}{reset}")
            print(f"{cyan}░{reset}" * terminal_size)
      try:
            user_input = prompt("\n", multiline=True)
            return user_input
      except:
            return None

def burplike_header_string_process(header_string=""):
      _URL = ""
      _METHOD = ""
      _HOST = ""
      _PATH = ""
      _COOKIES = []
      _OTHERS = {}
      _PAYLOADS = {}
      burp_header_string = header_string
      if burp_header_string:
            # detecting if header string have boundary data
            if "content-disposition" in burp_header_string.lower():
                  field_names = re.findall(r'name=[\'\"](.*?)[\'\"]', burp_header_string)
                  contents = re.findall(r'[Cc]ontent\-[Dd]isposition.*?\n(?:;Ccontent\-Ttype\:\n)*(.*?)---', burp_header_string, re.DOTALL)
                  for _hkey, _hval in zip(field_names, contents):
                        _PAYLOADS[_hkey] = _hval.strip()
            for header_line in burp_header_string.split("\n"):
                  # detecting the HTTP METHOD and PATH line
                  if re.match(r'([A-Z]{0,6}) (/.*?) HTTP/', header_line) and "HTTP/" in header_line:
                        _METHOD = re.match(r'([A-Z]{0,6}) (/.*?) HTTP/', header_line).group(1)
                        _PATH = re.match(r'([A-Z]{0,6}) (/.*?) HTTP/', header_line).group(2)
                  elif re.match(r'Cookie: (.*?)\n', header_line):
                        _COOKIES.append(re.match(r'Cookie: (.*?)\n', header_line).group(1))
                  # detecting other headers
                  elif re.match(r'[a-zA-Z\-]+\:',header_line):
                        _hkey = header_line.lower().split(" ")[0].replace(":","")
                        _hval = " ".join(header_line.lower().split(" ")[1:])
                        _OTHERS[_hkey] = _hval
                  else:
                        try:
                              _payload = json.loads(header_line)
                              _PAYLOADS = _payload
                        except:
                              if re.match(r'(&?[^&=]+=[^&=]+)', header_line):
                                    for _item in header_line.split("&"):
                                          _hkey, _hval = _item.split("=")
                                          _PAYLOADS[_hkey] = unquote_plus(_hval)
            _URL = "https://" + _OTHERS['host'] + _PATH
            _COOKIES = " ;".join(_COOKIES) if len(_COOKIES) > 1 else _COOKIES[0] if _COOKIES else ""
            if _COOKIES:
                  _OTHERS['cookie'] = _COOKIES
      request_data = {
            "_URL":_URL,
            "_METHOD": _METHOD,
            "_HEADERS": _OTHERS,
            "_PAYLOADS": _PAYLOADS
      }

      return request_data
def perform_request(_request):
      _URL = _request.get("_URL")
      _METHOD = _request.get("_METHOD")
      _HEADERS = _request.get("_HEADERS",{})
      _PAYLOADS = _request.get("_PAYLOADS",{})
      # os.system('clear')
      _HEADERS.pop('content-length')
      if "x-www-form-urlencoded" in _HEADERS['content-type']:
            req = _requester.request(url=_URL, method=_METHOD, headers=_HEADERS, data=_PAYLOADS)
      else:
            req = _requester.request(url=_URL, method=_METHOD, headers=_HEADERS, json=_PAYLOADS)

      print(req.text)

def prepare_request():
      header_string = burplike_header_string_input(f"Type or paste your header string. Use arrow to move the cursor\nESC + ENTER for cancel or if you're done")
      if "content-disposition" in header_string.lower() and "filename=" in header_string.lower():
            exit()
      parsed_headers = burplike_header_string_process(header_string)
      perform_request(parsed_headers)
if __name__ == "__main__":
      prepare_request()