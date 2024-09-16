#!/usr/bin/python3

import requests
from pprint import pprint
import urllib3
from xml.etree import ElementTree
from lxml import etree
import json
from tabulate import tabulate
from datetime import datetime
import base64
import argparse
import textwrap

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ns = '{http://xmlns.sony.net/d-cinema/sms/2007b}'

def parse_args():
    """ Parse command line arguments """

    parser = argparse.ArgumentParser(
        description='Get all CPL from the Sony Projector',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(f'''\
            Author: Christian Blechert <christian.blechert@neu-deli.de>
            Website: https://github.com/NEU-Deli/SRX-R515-Tools
            ''')
        )

    parser.add_argument('--server', type=str, required=True, help='Projector Server IP address', default='172.23.31.101')
    parser.add_argument('--username', type=str, required=False, help='SMS username', default='showmgr')
    parser.add_argument('--password', type=str, required=False, help='SMS password', default='2222')

    parser.add_argument('--markdown', action='store_true', help='Output as Markdown Table', default=False)

    return parser.parse_args()

class SRXR515:

    def __init__(self, server: str, username: str, password: str):
        self.server = server
        self.username = username
        self.password = password
        self.s = requests.Session()

    def query(self, url, headers={}):
        """ Make a web request to the projector """

        rurl = f"https://{self.server}{url}"
        dheaders = {
            'Accept': 'text/xml',
            'Content-Type': 'text/xml; charset=utf-8'
        }

        rheaders = { **dheaders, **headers }
        return self.s.get(rurl, headers=rheaders, data={}, verify=False)

    def login(self):
        """ Perform a login """

        authinfo = base64.b64encode(bytes(f"{self.username}:{self.password}", 'utf-8')).decode('utf-8')
        response = self.query('/login', { 'Authorization': f"Basic {authinfo}" })

        return '<RealName>Show+Manager</RealName>' in response.text

    def logout(self):
        """ Perform a logout """

        response = self.query('/logout')
        return response.status_code == 204

    def cpllist(self):
        """ Get all CPL """

        cplresponse = self.query('/content/cpl/info/list?detailed=true&emitplayable=true')
        cpltree = ElementTree.fromstring(cplresponse.text)

        cpllist = cpltree \
            .find(ns+'MessageBody') \
            .find(ns+'CPLDetailsList') \
            .iter(ns+'CPLDetails')

        for cplitem in cpllist:
            yield {
                'id': cplitem.find(ns+'ID').text,
                'title': cplitem.find(ns+'ContentTitle').text,
                'type': cplitem.find(ns+'ContentType').text,
                'version': cplitem.find(ns+'ContentVersion').text,
                'videoPlayStatus': cplitem.find(ns+'VideoPlayStatus').text == 'OK',
                'videoEncrypted': cplitem.find(ns+'EncryptionFlags').find(ns+'EncryptedVideo').text == 'True',
                'audioPlayStatus': cplitem.find(ns+'AudioPlayStatus').text == 'OK',
                'audioEncrypted': cplitem.find(ns+'EncryptionFlags').find(ns+'EncryptedAudio').text == 'True',
                'isPlayable': cplitem.find(ns+'IsPlayable').text == 'true',
                'auxPlayStatus': cplitem.find(ns+'AuxPlayStatus').text,
                'frameRateNumerator': int(cplitem.find(ns+'FrameRate').find(ns+'Numerator').text),
                'frameRateDenominator': int(cplitem.find(ns+'FrameRate').find(ns+'Denominator').text),
                'aspectRatioWidth': int(cplitem.find(ns+'AspectRatio').find(ns+'Width').text),
                'aspectRatioHeight': int(cplitem.find(ns+'AspectRatio').find(ns+'Height').text),
                'channelCount': int(cplitem.find(ns+'NumberOfChannels').text),
                'videoEncrypted': cplitem.find(ns+'EncryptionFlags').find(ns+'EncryptedVideo').text == 'true',
                'audioEncrypted': cplitem.find(ns+'EncryptionFlags').find(ns+'EncryptedAudio').text == 'true',
                'reelCount': int(cplitem.find(ns+'NumberOfReels').text),
                'length': int(cplitem.find(ns+'RunningTime').text),
                'dimension': cplitem.find(ns+'Dimension').text,
                'issuer': cplitem.find(ns+'CplIssuer').text,
                'complete': cplitem.find(ns+'Complete').text == 'true',
                'subtitlesEnabled': cplitem.find(ns+'IsSubtitleEnabled').text == 'true',
                'verticalShift': int(cplitem.find(ns+'VerticalShift').text),
                'horizontalShift': int(cplitem.find(ns+'HorizontalShift').text),
                'magnification': float(cplitem.find(ns+'Magnification').text),
            }

    def cplkdmlist(self, cplid):
        """ Get KDMs for a CPL """

        kdmresponse = self.query('/content/kdm/info?Id=' + cplid)
        kdmtree = ElementTree.fromstring(kdmresponse.text)

        if kdmtree.find(ns+'MessageHeader').find(ns+'Type').text != 'KDMDetailsList':
            return

        kdmlist = kdmtree \
            .find(ns+'MessageBody') \
            .find(ns+'KDMDetailsList') \
            .iter(ns+'KDMDetails')

        for kdmitem in kdmlist:
            yield {
                'cplid': kdmitem.find(ns+'CPLID').text,
                'kdmid': kdmitem.find(ns+'KDMID').text,
                'importTime': int(kdmitem.find(ns+'ImportTime').text),
                'validStart': int(kdmitem.find(ns+'ValidStartTerm').text),
                'validEnd': int(kdmitem.find(ns+'ValidEndTerm').text),
            }

def transform(data, api):
    """ Create more properties in a CPL item """

    for item in data:
        item['isEncrypted'] = item['videoEncrypted'] or item['audioEncrypted']
        item['isAllPlayable'] = item['videoPlayStatus'] and item['audioPlayStatus'] and item['isPlayable']
        item['kdmStarts'] = []
        item['kdmEnds'] = []

        kdmlist = list(api.cplkdmlist(item['id']))
        for kdmitem in kdmlist:
            item['kdmStarts'].append(datetime.utcfromtimestamp(kdmitem['validStart']).isoformat())
            item['kdmEnds'].append(datetime.utcfromtimestamp(kdmitem['validEnd']).isoformat())

        yield item

def headeredtabledata(data, header):
    """ Convert a dict into a list[][] by header """

    for item in data:
        row = []
        for col in header:
            row.append(item[col])
        yield row

def markdownTable(data, header):
    """ Create a markdown table """

    yield '|'
    for item in header:
        yield f" {item} |"
    yield '\n|'
    for _ in header:
        yield '---|'
    for row in data:
        yield '\n|'
        for col in row:
            if isinstance(col, list):
                yield f" {'<br>'.join(col)} |"
            else:
                yield f" {col} |"

def main():
    """ Main function """

    args = parse_args()
    api = SRXR515(args.server, args.username, args.password)

    if not api.login():
        raise Exception('Login failed.')

    cpls = list(api.cpllist())

    header = [ 'type', 'isAllPlayable', 'isEncrypted',  'title', 'kdmStarts', 'kdmEnds' ]
    displayHeader = [ 'type', 'playable?', 'encrypted?', 'title', 'kdmFrom', 'kdmTo' ]
    sorter = lambda x: (x['type'], x['title'])

    prepareddata = sorted(transform(cpls, api), key=sorter)

    if not api.logout():
        raise Exception('Logout failed')

    if args.markdown:
        print(''.join(list(markdownTable(headeredtabledata(prepareddata, header), displayHeader))))
    else:
        print(tabulate(headeredtabledata(prepareddata, header), headers=displayHeader))

# start main function
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # catch exception when script was canceled by CTRL+C
        pass
