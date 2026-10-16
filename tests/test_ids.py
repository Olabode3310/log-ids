import unittest
from parsers.logs import parse_line
from detectors.rules import detect_rules
from detectors.anomaly import detect_anomalies
class IdsTests(unittest.TestCase):
 def test_auth_parse(self):self.assertEqual(parse_line('Oct 16 08:11:03 web sshd[1]: Failed password for root','auth')['source'],'auth')
 def test_rule(self):self.assertEqual(detect_rules([{'message':'Failed password'}],{})[0]['rule'],'failed_login')
 def test_spike(self):self.assertEqual(detect_anomalies([{'message':'Failed password','host':'x'}]*5,{'failed_login_threshold':5})[0]['rule'],'failed_login_spike')
if __name__=='__main__':unittest.main()
