import whitelist
from unittest.mock import patch
from whitelist import findSecurityGroups, getpublicip
import moto
from moto import mock_ec2
import unittest




    

class WhitelistTestCase(unittest.TestCase):
    # test if it will return something with sg-
    @mock_ec2
    def test_find_sg_processed_input_correctly(self):
        user_input = "1"
        expected_sg = "sg-"
        with patch('builtins.input', side_effect=user_input):
            sg = findSecurityGroups().split("-")
        self.assertIn(sg[0], expected_sg)
        user_input = "0"
        expected_sg = "sg-"
        with patch('builtins.input', side_effect=user_input):
            sg = findSecurityGroups().split("-")
        self.assertIn(sg[0], expected_sg)
        user_input = "6"

    #test if its a ip address 
    def test_ip_find_correctly(self):
        self.assertRegex(getpublicip(),"^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$")
       


if __name__ == '__main__':
    unittest.main()