#!/usr/bin/env python3

# tshark -r usb.pcapng -Y usb -T fields -e usb.capdata > usbdata.txt

# shift map

# letters
shift_map = {
  'a' : 'A',
  'b' : 'B',
  'c' : 'C',
  'd' : 'D',
  'e' : 'E',
  'f' : 'F',
  'g' : 'G',
  'h' : 'H',
  'i' : 'I',
  'j' : 'J',
  'k' : 'K',
  'l' : 'L',
  'm' : 'M',
  'n' : 'N',
  'o' : 'O',
  'p' : 'P',
  'q' : 'Q',
  'r' : 'R',
  's' : 'S',
  't' : 'T',
  'u' : 'U',
  'v' : 'V',
  'w' : 'W',
  'x' : 'X',
  'y' : 'Y',
  'z' : 'Z',
  # numbers
  '1' : '!',
  '2' : '@',
  '3' : '#',
  '4' : '$',
  '5' : '%',
  '6' : '^',
  '7' : '&',
  '8' : '*',
  '9' : '(',
  '0' : ')',
  # symbols
  '-' : '_',
  '=' : '+',
  '[' : '{',
  ']' : '}',
  '\\' : '|',
  ';' : ':',
  '\'' : '"',
  ',' : '<',
  '.' : '>',
  '/' : '?',
  '`' : '~'
}

# hex map

# modifier keys
mod_keys = {
  '00' : '',
  '01' : 'left_ctrl',
  '02' : 'left_shift',
  '04' : 'left_alt',
  '08' : 'left_meta',
  '10' : 'right_ctrl',
  '20' : 'right_shift',
  '40' : 'right_alt',
  '80' : 'right_meta'
}

# base keys

base_keys = {
  # meta
  '00' : '', # none
  '01' : 'error_ovf',
  # letters
  '04' : 'a',
  '05' : 'b',
  '06' : 'c',
  '07' : 'd',
  '08' : 'e',
  '09' : 'f',
  '0a' : 'g',
  '0b' : 'h',
  '0c' : 'i',
  '0d' : 'j',
  '0e' : 'k',
  '0f' : 'l',
  '10' : 'm',
  '11' : 'n',
  '12' : 'o',
  '13' : 'p',
  '14' : 'q',
  '15' : 'r',
  '16' : 's',
  '17' : 't',
  '18' : 'u',
  '19' : 'v',
  '1a' : 'w',
  '1b' : 'x',
  '1c' : 'y',
  '1d' : 'z',
  # numbers
  '1e' : '1',
  '1f' : '2',
  '20' : '3',
  '21' : '4',
  '22' : '5',
  '23' : '6',
  '24' : '7',
  '25' : '8',
  '26' : '9',
  '27' : '0',
  # misc
  '28' : '\n', #enter
  '29' : 'esc',
  '2a' : 'backspace',
  '2b' : 'tab',
  '2c' : ' ', #space
  '2d' : '-',
  '2e' : '=',
  '2f' : '[',
  '30' : ']',
  '31' : '\\',
  '32' : '=',
  '33' : '_SEMICOLON',
  '34' : 'KEY_APOSTROPHE',
  '35' : 'KEY_GRAVE',
  '36' : 'KEY_COMMA',
  '37' : 'KEY_DOT',
  '38' : 'KEY_SLASH',
  '39' : 'KEY_CAPSLOCK',
  '3a' : 'KEY_F1',
  '3b' : 'KEY_F2',
  '3c' : 'KEY_F3',
  '3d' : 'KEY_F4',
  '3e' : 'KEY_F5',
  '3f' : 'KEY_F6',
  '40' : 'KEY_F7',
  '41' : 'KEY_F8',
  '42' : 'KEY_F9',
  '43' : 'KEY_F10',
  '44' : 'KEY_F11',
  '45' : 'KEY_F12',
  '46' : 'KEY_SYSRQ',
  '47' : 'KEY_SCROLLLOCK',
  '48' : 'KEY_PAUSE',
  '49' : 'KEY_INSERT',
  '4a' : 'KEY_HOME',
  '4b' : 'KEY_PAGEUP',
  '4c' : 'KEY_DELETE',
  '4d' : 'KEY_END',
  '4e' : 'KEY_PAGEDOWN',
  '4f' : 'KEY_RIGHT',
  '50' : 'KEY_LEFT',
  '51' : 'KEY_DOWN',
  '52' : 'KEY_UP',
  '53' : 'KEY_NUMLOCK',
  '54' : 'KEY_KPSLASH',
  '55' : 'KEY_KPASTERISK',
  '56' : 'KEY_KPMINUS',
  '57' : 'KEY_KPPLUS',
  '58' : 'KEY_KPENTER',
  '59' : 'KEY_KP1',
  '5a' : 'KEY_KP2',
  '5b' : 'KEY_KP3',
  '5c' : 'KEY_KP4',
  '5d' : 'KEY_KP5',
  '5e' : 'KEY_KP6',
  '5f' : 'KEY_KP7',
  '60' : 'KEY_KP8',
  '61' : 'KEY_KP9',
  '62' : 'KEY_KP0',
  '63' : 'KEY_KPDOT',
  '64' : 'KEY_102ND',
  '65' : 'KEY_COMPOSE',
  '66' : 'KEY_POWER',
  '67' : 'KEY_KPEQUAL',
  '68' : 'KEY_F13',
  '69' : 'KEY_F14',
  '6a' : 'KEY_F15',
  '6b' : 'KEY_F16',
  '6c' : 'KEY_F17',
  '6d' : 'KEY_F18',
  '6e' : 'KEY_F19',
  '6f' : 'KEY_F20',
  '70' : 'KEY_F21',
  '71' : 'KEY_F22',
  '72' : 'KEY_F23',
  '73' : 'KEY_F24',
  '74' : 'KEY_OPEN',
  '75' : 'KEY_HELP',
  '76' : 'KEY_PROPS',
  '77' : 'KEY_FRONT',
  '78' : 'KEY_STOP',
  '79' : 'KEY_AGAIN',
  '7a' : 'KEY_UNDO',
  '7b' : 'KEY_CUT',
  '7c' : 'KEY_COPY',
  '7d' : 'KEY_PASTE',
  '7e' : 'KEY_FIND',
  '7f' : 'KEY_MUTE',
  '80' : 'KEY_VOLUMEUP',
  '81' : 'KEY_VOLUMEDOWN',
  '85' : 'KEY_KPCOMMA',
  '87' : 'KEY_RO',
  '88' : 'KEY_KATAKANAHIRAGANA',
  '89' : 'KEY_YEN',
  '8a' : 'KEY_HENKAN',
  '8b' : 'KEY_MUHENKAN',
  '8c' : 'KEY_KPJPCOMMA',
  '90' : 'KEY_HANGEUL',
  '91' : 'KEY_HANJA',
  '92' : 'KEY_KATAKANA',
  '93' : 'KEY_HIRAGANA',
  '94' : 'KEY_ZENKAKUHANKAKU',
  'b6' : 'KEY_KPLEFTPAREN',
  'b7' : 'KEY_KPRIGHTPAREN',
  'e0' : 'KEY_LEFTCTRL',
  'e1' : 'KEY_LEFTSHIFT',
  'e2' : 'KEY_LEFTALT',
  'e3' : 'KEY_LEFTMETA',
  'e4' : 'KEY_RIGHTCTRL',
  'e5' : 'KEY_RIGHTSHIFT',
  'e6' : 'KEY_RIGHTALT',
  'e7' : 'KEY_RIGHTMETA',
  'e8' : 'KEY_MEDIA_PLAYPAUSE',
  'e9' : 'KEY_MEDIA_STOPCD',
  'ea' : 'KEY_MEDIA_PREVIOUSSONG',
  'eb' : 'KEY_MEDIA_NEXTSONG',
  'ec' : 'KEY_MEDIA_EJECTCD',
  'ed' : 'KEY_MEDIA_VOLUMEUP',
  'ee' : 'KEY_MEDIA_VOLUMEDOWN',
  'ef' : 'KEY_MEDIA_MUTE',
  'f0' : 'KEY_MEDIA_WWW',
  'f1' : 'KEY_MEDIA_BACK',
  'f2' : 'KEY_MEDIA_FORWARD',
  'f3' : 'KEY_MEDIA_STOP',
  'f4' : 'KEY_MEDIA_FIND',
  'f5' : 'KEY_MEDIA_SCROLLUP',
  'f6' : 'KEY_MEDIA_SCROLLDOWN',
  'f7' : 'KEY_MEDIA_EDIT',
  'f8' : 'KEY_MEDIA_SLEEP',
  'f9' : 'KEY_MEDIA_COFFEE',
  'fa' : 'KEY_MEDIA_REFRESH',
  'fb' : 'KEY_MEDIA_CALC'
}

with open('usbdata.txt', 'r') as fin:
    data = []
    for line in fin:
        line = line.strip()
        if len(line) == 0:
            continue
        data.append(line)

flag = ''
for line in data:
    line = bytes.fromhex(line)
    #line = line[1:]
    mod, reserved, *keys = line
    #assert line[8:] == b'\0'*8, line[8:]
    #print(mod, reserved, keys)
    #print(usb_codes.get(line[4]))
    key = base_keys.get(f'{keys[0]:02x}', '')
    shift = mod & 2 == 2
    alt = mod & 64 == 64
    
    if key == '':
        pass
    elif shift and key == 'KEY_SLASH':
        flag += '_'
    elif shift:
        key = shift_map[key]
        flag += key
    elif alt:
        print(shift, alt, key)
        flag += '?'
    else:
        flag += key

print(flag)
