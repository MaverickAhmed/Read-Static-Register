# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame

class Hla(HighLevelAnalyzer):
    # Result types to display decoded frames
    result_types = {
        'hex_data': {
            'format': 'HEX: {{data.hex}}'
        }
    }

    def __init__(self):
        '''
        Initialize HLA.
        '''
        self.fs_high = False
        self.fs_start_time = None
        self.bits = []

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.
        '''
        # Check for FS signal
        if frame.type == 'fs':
            if frame.data['value'] == 1:  # FS goes high
                self.fs_high = True
                self.fs_start_time = frame.start_time
                self.bits = []
            elif frame.data['value'] == 0:  # FS goes low
                if self.fs_high and len(self.bits) == 384:  # Only process if exactly 384 bits
                    hex_value = self.bits_to_hex(self.bits)
                    # Return the HEX value as a new AnalyzerFrame
                    return AnalyzerFrame('hex_data', self.fs_start_time, frame.end_time, {
                        'hex': hex_value
                    })
                self.fs_high = False

        # Check for SDA0 signal and capture bits
        if self.fs_high and frame.type == 'sda0':
            self.bits.append(frame.data['value'])

        return None

    def bits_to_hex(self, bits):
        '''
        Convert a list of bits to a hexadecimal string.
        '''
        hex_string = ''
        for i in range(0, len(bits), 4):
            nibble = bits[i:i+4]
            hex_string += '{:X}'.format(int(''.join(map(str, nibble)), 2))
        return hex_string
