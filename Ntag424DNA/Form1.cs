using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Runtime.InteropServices;  //调用动态库一定要加入这个引用

namespace Ntag424DNA
{
    public partial class Form1 : Form
    {
        //外部函数声明：让设备发出声响--------------------------------------------------------------------------------------------------------------------------
        [DllImport("OUR_MIFARE.dll", EntryPoint = "pcdbeep", CallingConvention = CallingConvention.StdCall)]
        static extern byte pcdbeep(Int32 xms);//xms单位为毫秒 

        //读取设备编号，可做为软件加密狗用,也可以根据此编号在公司网站上查询保修期限-----------------------------------------------------------------------------
        [DllImport("OUR_MIFARE.dll", EntryPoint = "pcdgetdevicenumber", CallingConvention = CallingConvention.StdCall)]
        static extern byte pcdgetdevicenumber(byte[] devicenumber);//devicenumber用于返回编号 

        //获取IC卡芯片型号---------------------------------------------------------------------------------------------------------------------------------------- 
        [DllImport("OUR_MIFARE.dll", EntryPoint = "getmifareversion")]
        static extern byte getmifareversion(byte[] cardtypestr, byte[] AtqaSak, byte[] versionbuf, byte[] versionlen, byte[] retsw);

        //激活Desfire卡、CPU卡------------------------------------------------------------------------------------------------------------------------------------ 
        [DllImport("OUR_MIFARE.dll", EntryPoint = "cpurequest1")]
        static extern byte cpurequest1(byte[] mypiccserial, byte[] myparam, byte[] myver, byte[] mycode, byte[] AtqaSak);

        //CPU卡发送接收调试--------------------------------------------------------------------------------------------------------------------------------------- 
        [DllImport("OUR_MIFARE.dll", EntryPoint = "cpuisoapdu")]
        static extern byte cpuisoapdu(byte[] sendbuf, Int32 datalen, byte[] revbuf, byte[] revlen);

        //EV2密钥认证---------------------------------------------------------------------------------------------------------------------------------------------
        [DllImport("OUR_MIFARE.dll", EntryPoint = "desfireauthkeyev2")]
        static extern byte desfireauthkeyev2(byte[] keybuf, byte keyid, byte authmode, byte[] retsw);

        //更改卡密钥---------------------------------------------------------------------------------------------------------------------------------
        [DllImport("OUR_MIFARE.dll", EntryPoint = "ntagchangkey")]
        static extern byte ntagchangkey(byte[] newkeybuf, byte keyid, byte onecode, byte[] oldkeybuf, byte[] retsw);

        //更改随机UID---------------------------------------------------------------------------------------------------------------------------------
        [DllImport("OUR_MIFARE.dll", EntryPoint = "ntagsetconfiguration")]
        static extern byte ntagsetconfiguration(byte ctr, byte[] setbuf, byte beflen,  byte[] retsw);

        //------------------------------------------------------------------------------------------------------------------------------------------------------    
        //清空ForumType4类标签NDEF数据缓冲
        [DllImport("OUR_MIFARE.dll", EntryPoint = "tagbuf_forumtype4_clear", CallingConvention = CallingConvention.StdCall)]
        static extern byte tagbuf_forumtype4_clear();//

        //------------------------------------------------------------------------------------------------------------------------------------------------------    
        //生成NDEF URI数据缓冲
        [DllImport("OUR_MIFARE.dll", EntryPoint = "tagbuf_adduri", CallingConvention = CallingConvention.StdCall)]
        static extern byte tagbuf_adduri(string languagecodestr, int languagecodestrlen, string titlestr, int titlestrlen, int uriheaderindex, string uristr, int uristrlen);
        
        //------------------------------------------------------------------------------------------------------------------------------------------------------    
        //将NDEF数据缓冲写入ForumType4标签 
        [DllImport("OUR_MIFARE.dll", EntryPoint = "forumtype4_write_ndeftag", CallingConvention = CallingConvention.StdCall)]
        static extern byte forumtype4_write_ndeftag(byte ctrlword, byte[] serial, byte[] seriallen, byte[] ndefwritekey);

        //------------------------------------------------------------------------------------------------------------------------------------------------------    
        //读取ForumType4标签内的NDEF信息
        [DllImport("OUR_MIFARE.dll", EntryPoint = "forumtype4_read_ndeftag", CallingConvention = CallingConvention.StdCall)]
        static extern byte forumtype4_read_ndeftag(byte ctrlword, byte[] serial, byte[] seriallen, byte[] ndefwritekey);

        //------------------------------------------------------------------------------------------------------------------------------------------------------    
        //解析数据缓冲中的NDEF信息
        [DllImport("OUR_MIFARE.dll", EntryPoint = "tagbuf_read", CallingConvention = CallingConvention.StdCall)]
        static extern byte tagbuf_read(byte[] revstr, byte[] revstrlen, byte[] recordnumber);

        //------------------------------------------------------------------------------------------------------------------------------------------------------    
        //修改424卡配置信息
        [DllImport("OUR_MIFARE.dll", EntryPoint = "ntagchangefilesettings", CallingConvention = CallingConvention.StdCall)]
        static extern byte ntagchangefilesettings(byte commmode, byte fileno, byte[] settingsbuf, int settingslen, byte[] retsw);

        //------------------------------------------------------------------------------------------------------------------------------------------------------    
        //读取424卡配置信息
        [DllImport("OUR_MIFARE.dll", EntryPoint = "ntagreadfilesettings", CallingConvention = CallingConvention.StdCall)]
        static extern byte ntagreadfilesettings(byte commmode, byte fileno, byte[] settingsbuf, byte[] revbuflen, byte[] retsw);

        //------------------------------------------------------------------------------------------------------------------------------------------------------    
        //读取424卡真实卡号
        [DllImport("OUR_MIFARE.dll", EntryPoint = "forumtype4getuid", CallingConvention = CallingConvention.StdCall)]
        static extern byte forumtype4getuid(byte[] mypiccserial, byte[] mypiccseriallen, byte[] picckey);

        //-------------------------------------------------------------------------------------------------------------------------------------------------------
        [DllImport("kernel32", CharSet = CharSet.Unicode)]
        public static extern uint GetPrivateProfileString(string lpAppName, string lpKeyName, string lpDefault, StringBuilder lpReturnedString, uint nSize, string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        public static extern long WritePrivateProfileString(string section, string key, string val, string filePath);

        public Form1()
        {
            InitializeComponent();
        }

        public static string sGetINI(string strPath, string strSection, string strKey, string strDefault)
        {
            StringBuilder returnString = new StringBuilder(255); // 返回值存储区
            uint bufferSize = (uint)returnString.Capacity;
            uint result = GetPrivateProfileString(strSection, strKey, strDefault, returnString, bufferSize, strPath);
            return returnString.ToString();
        }

        public static void writeINI(string strPath, string strSection, string strKey, string strValue)
        {
            WritePrivateProfileString(strSection, strKey, strValue, strPath);
        }

        private static byte MessageDispInfo(byte errno)
        {
            switch (errno)
            {
                case 0:
                    MessageBox.Show("Operation successful!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    break;
                case 8:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", card not found. Please remove and replace the card on the reader!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 23:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", driver error or not installed!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 24:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", operation timed out, DLL not responding!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 25:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", insufficient bytes sent!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 26:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", sent CRC error!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 27:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", insufficient bytes received!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 28:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", received CRC error!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 47:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", read file failed. Please check if comm mode is correct!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 50:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", RATS error (manufacturer debug code, can be ignored)!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 51:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", PPS error (manufacturer debug code, can be ignored)!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 52:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", already in ISO 14443-4 protocol state, all CPU card operations available!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 53:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", CPU card communication error!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 54:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", insufficient data, remaining data needs to be sent to card!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 55:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", send ACK to card to request more data!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 56:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", failed to clear root directory!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 57:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", card does not support Forum_Type4 protocol. Please authenticate first by checking 'Requires Auth Key', then retry. If this still appears, the card may not be a Forum_Type4_Tag card!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 58:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", card initialization failed!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 59:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", insufficient allocated space!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 60:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", the entity already exists!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 61:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", insufficient space!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 62:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", file does not exist!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 63:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", insufficient permissions. Possibly authenticated with read-only key, unable to change read-write key or write file!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 64:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", key does not exist or key file not created!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 65:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", transfer length error!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 66:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", Le error, specified receive data length too large!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 67:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", function not supported, no MF in card, or card is locked!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 68:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", too many wrong password attempts, key is locked!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 86:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", new key length must match the original key length!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 87:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", application directory does not exist!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 88:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", application file does not exist!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;                
                case 90:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", returned data length insufficient when reading file, data may be incorrect!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 91:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", single read length cannot exceed 255!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 92:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", single write length cannot exceed 247!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 70:
                case 71:
                case 72:
                case 73:
                case 74:
                case 75:
                case 76:
                case 77:
                case 78:
                case 79:
                case 80:
                case 81:
                case 82:
                case 83:
                case 84:
                case 85:
                    MessageBox.Show("Error code: " + errno.ToString("D") + ", wrong password, remaining attempts: " + Convert.ToString(errno - 70) + ". If 0, this key will be permanently locked.", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                default:
                    MessageBox.Show("Operation failed, error code: " + Convert.ToString(errno), "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
            }
            return 0;
        }

        //判断16进制数据是否正确
        public static bool checkhexstr(string inputstr, int hexlen, byte[] bytebuf)
        {
            try
            {
                inputstr = inputstr.Replace(" ", "");
                inputstr = inputstr.Replace("\r", "");
                inputstr = inputstr.Replace("\n", "");
                for (int i = 0; i < hexlen; i++)
                {
                    bytebuf[i] = Convert.ToByte(Convert.ToInt32(inputstr.Substring(i * 2, 2), 16));
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        //卡操作返回代码解析
        public static string RetTextFromStr(string inputstr)
        {
            string RetTextFromStr = "";
            switch (inputstr)
            {
                case "9000":
                    RetTextFromStr = "Success!";
                    pcdbeep(20);
                    break;
                case "9100":
                    RetTextFromStr = "Success!";
                    pcdbeep(20);
                    break;
                case "6281":
                    RetTextFromStr = "Returned data may be incorrect!";
                    break;
                case "6283":
                    RetTextFromStr = "Selected file invalid, file or key checksum error";
                    break;
                case "6400":
                    RetTextFromStr = "Status flag not changed";
                    break;
                case "6581":
                    RetTextFromStr = "EEPROM write failed!";
                    break;
                case "6700":
                    RetTextFromStr = "Length error";
                    break;
                case "6900":
                    RetTextFromStr = "CLA does not match line protection requirements";
                    break;
                case "6901":
                    RetTextFromStr = "Invalid state!";
                    break;
                case "6981":
                    RetTextFromStr = "Command incompatible with file structure";
                    break;
                case "6982":
                    RetTextFromStr = "Security condition not satisfied";
                    break;
                case "6983":
                    RetTextFromStr = "Key is locked!";
                    break;
                case "6984":
                    RetTextFromStr = "MAC format mismatch";
                    break;
                case "6985":
                    RetTextFromStr = "Usage conditions not satisfied";
                    break;
                case "6986":
                    RetTextFromStr = "Please select a file first!";
                    break;
                case "6987":
                    RetTextFromStr = "No secure messaging";
                    break;
                case "6988":
                    RetTextFromStr = "Secure messaging data item incorrect";
                    break;
                case "6A80":
                    RetTextFromStr = "Data field parameter error!";
                    break;
                case "6A81":
                    RetTextFromStr = "Function not supported, no MF in card, or card is locked";
                    break;
                case "6A82":
                    RetTextFromStr = "File not found";
                    break;
                case "6A83":
                    RetTextFromStr = "Record not found!";
                    break;
                case "6A84":
                    RetTextFromStr = "Insufficient space in file";
                    break;
                case "6A86":
                    RetTextFromStr = "Parameter P1 P2 error";
                    break;
                case "6A88":
                    RetTextFromStr = "Key not found!";
                    break;
                case "6B00":
                    RetTextFromStr = "File end reached before Le/Lc bytes, offset error";
                    break;
                case "6E00":
                    RetTextFromStr = "Invalid CLA";
                    break;
                case "6F00":
                    RetTextFromStr = "Invalid data!";
                    break;
                case "9302":
                    RetTextFromStr = "MAC error";
                    break;
                case "9303":
                    RetTextFromStr = "Application is locked";
                    break;
                case "9401":
                    RetTextFromStr = "Insufficient balance!";
                    break;
                case "9403":
                    RetTextFromStr = "Key not found!";
                    break;
                case "9406":
                    RetTextFromStr = "Required MAC not available!";
                    break;
                case "91AE":
                    RetTextFromStr = "Authentication failed, please check parameters and calculations!";
                    break;
                case "91CA":
                    RetTextFromStr = "Previous command not fully completed!";
                    break;
                case "917E":
                    RetTextFromStr = "Instruction length error!";
                    break;
                case "9140":
                    RetTextFromStr = "Current directory or application key does not exist, please select the correct directory or application first!";
                    break;
                case "919D":
                    RetTextFromStr = "Password not verified, this command cannot operate!";
                    break;
                case "911E":
                    RetTextFromStr = "MAC error!";
                    break;
                case "91F0":
                    RetTextFromStr = "This file number does not exist!";
                    break;
                case "919E":
                    RetTextFromStr = "Invalid parameter!";
                    break;
                case "91BE":
                    RetTextFromStr = "Attempted to read/write data beyond file/record boundaries!";
                    break;
                case "91A0":
                    RetTextFromStr = "Requested AID does not exist!";
                    break;
                default:
                    if (inputstr.Substring(0, 3) == "63C")
                    {
                        int i = Convert.ToInt16(inputstr.Substring(3, 1), 16);
                        if (i > 0)
                        {
                            RetTextFromStr = i.ToString("D") + " more wrong attempts will lock this key!";
                        }
                        else { RetTextFromStr = "Key is locked"; }
                    }
                    else
                    {
                        RetTextFromStr = "Unknown exception";
                    }
                    break;
            }

            return RetTextFromStr;
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            comboBox1.SelectedIndex = 0;
            comboBox14.SelectedIndex = 0;

            comboBox5.SelectedIndex = 0;            

            comboBox7.SelectedIndex = 0;
            comboBox8.SelectedIndex = 5;
            comboBox9.SelectedIndex = 5;
            comboBox10.SelectedIndex = 5;
            comboBox11.SelectedIndex = 0;

            comboBox13.SelectedIndex = 0;

            String Titlestr = sGetINI("./syssetup.ini", "DefaultSetup", "textBox4", "");
            String UriStr = sGetINI("./syssetup.ini", "DefaultSetup", "textBox5", "");
            if (Titlestr != "" || UriStr != "")
            {
                textBox4.Text = Titlestr;
                comboBox4.SelectedIndex = int.Parse(sGetINI("./syssetup.ini", "DefaultSetup", "comboBox4", "0"));
                textBox5.Text = UriStr;

                comboBox7.SelectedIndex = int.Parse(sGetINI("./syssetup.ini", "DefaultSetup", "comboBox7", "0"));
                comboBox8.SelectedIndex = int.Parse(sGetINI("./syssetup.ini", "DefaultSetup", "comboBox8", "5"));
                comboBox9.SelectedIndex = int.Parse(sGetINI("./syssetup.ini", "DefaultSetup", "comboBox9", "5"));
                comboBox10.SelectedIndex = int.Parse(sGetINI("./syssetup.ini", "DefaultSetup", "comboBox10", "5"));
                comboBox11.SelectedIndex = int.Parse(sGetINI("./syssetup.ini", "DefaultSetup", "comboBox11", "0"));

                if (sGetINI("./syssetup.ini", "DefaultSetup", "checkBox6", "") == "1")
                {
                    checkBox6.Checked = true;
                }
                else { checkBox6.Checked = false; }
                numericUpDown_keyid.Value = int.Parse(sGetINI("./syssetup.ini", "DefaultSetup", "numericUpDown_keyid", "0"));
                textBox8.Text = sGetINI("./syssetup.ini", "DefaultSetup", "textBox8", "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
                comboBox13.SelectedIndex = int.Parse(sGetINI("./syssetup.ini", "DefaultSetup", "comboBox13", "0"));

                if (sGetINI("./syssetup.ini", "DefaultSetup", "checkBox_SDM", "") == "1")
                {
                    checkBox_SDM.Checked = true;
                }
                else { checkBox_SDM.Checked = false ; }

                if (sGetINI("./syssetup.ini", "DefaultSetup", "checkBox_UID", "") == "1")
                {
                    checkBox_UID.Checked = true;
                }
                else { checkBox_UID.Checked = false; }

                if (sGetINI("./syssetup.ini", "DefaultSetup", "checkBox_CounterMirror", "") == "1")
                {
                    checkBox_CounterMirror.Checked = true;
                }
                else { checkBox_CounterMirror.Checked = false; }

                if (sGetINI("./syssetup.ini", "DefaultSetup", "checkBox_CounterLimit", "") == "1")
                {
                    checkBox_CounterLimit.Checked = true;
                }
                else { checkBox_CounterLimit.Checked = false; }

                if (sGetINI("./syssetup.ini", "DefaultSetup", "checkBox_SDMNCF", "") == "1")
                {
                    checkBox_SDMNCF.Checked = true;
                }
                else { checkBox_SDMNCF.Checked = false; }                                

                comboBox_SdmPower.SelectedIndex = int.Parse(sGetINI("./syssetup.ini", "DefaultSetup", "comboBox_SdmPower", "0"));
                comboBox_cmackey.SelectedIndex = int.Parse(sGetINI("./syssetup.ini", "DefaultSetup", "comboBox_cmackey", "6"));
                comboBox_counterkey.SelectedIndex = int.Parse(sGetINI("./syssetup.ini", "DefaultSetup", "comboBox_counterkey", "6"));

                numericUpDown1.Value = int.Parse(sGetINI("./syssetup.ini", "DefaultSetup", "numericUpDown1", "0"));
                numericUpDown2.Value = int.Parse(sGetINI("./syssetup.ini", "DefaultSetup", "numericUpDown2", "0"));
                numericUpDown3.Value = int.Parse(sGetINI("./syssetup.ini", "DefaultSetup", "numericUpDown3", "26"));
                numericUpDown4.Value = int.Parse(sGetINI("./syssetup.ini", "DefaultSetup", "numericUpDown4", "0"));
                numericUpDown5.Value = int.Parse(sGetINI("./syssetup.ini", "DefaultSetup", "numericUpDown5", "0"));
                numericUpDown6.Value = int.Parse(sGetINI("./syssetup.ini", "DefaultSetup", "numericUpDown6", "0"));
                numericUpDown7.Value = int.Parse(sGetINI("./syssetup.ini", "DefaultSetup", "numericUpDown7", "0"));
                numericUpDown8.Value = int.Parse(sGetINI("./syssetup.ini", "DefaultSetup", "numericUpDown8", "0"));
            }
            else
            {
                button5.PerformClick();
            }
        }

        private void button4_Click(object sender, EventArgs e)
        {
            byte status = pcdbeep(50);
            if (status != 0)
            {
                MessageDispInfo(status);
            }
        }

        private void button8_Click(object sender, EventArgs e)
        {
            byte[] devno = new byte[4];
            byte status = pcdgetdevicenumber(devno);
            if (status == 0)
            {
                pcdbeep(50);
                MessageBox.Show("Device serial number: " + devno[0].ToString("D3") + "-" + devno[1].ToString("D3") + "-" + devno[2].ToString("D3") + "-" + devno[3].ToString("D3"), "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else { MessageDispInfo(status); }
        }

        private void button7_Click(object sender, EventArgs e)
        {
            byte[] AtqaSak = new byte[3];
            byte[] retsw = new byte[2];
            byte[] versionbuf = new byte[100];
            byte[] versionlen = new byte[2];
            byte[] cardtypebuf = new byte[1024];

            byte status = getmifareversion(cardtypebuf, AtqaSak, versionbuf, versionlen, retsw);
            string cardtypestr = Encoding.ASCII.GetString(cardtypebuf).Trim();
            string retstr = retsw[0].ToString("X2") + retsw[1].ToString("X2");
            if (status > 0)
            {
                MessageDispInfo(status);
            }
            else
            {
                pcdbeep(20);
                MessageBox.Show("Get IC card chip model, card return code: " + retstr + "\r\nModel: " + cardtypestr, "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private void comboBox1_SelectedIndexChanged(object sender, EventArgs e)
        {
            switch (comboBox1.SelectedIndex)
            {
                case 0:
                    comboBox2.SelectedIndex = 0;
                    comboBox3.SelectedIndex = 0;
                    textBox2.Text = "D2 76 00 00 85 01 00";
                    break;
                case 1:
                    comboBox2.SelectedIndex = 1;
                    comboBox3.SelectedIndex = 0;
                    textBox2.Text = "3F 00";
                    break;
                case 2:
                    comboBox2.SelectedIndex = 0;
                    comboBox3.SelectedIndex = 0;
                    textBox2.Text = "D2 76 00 00 85 01 01";
                    break;
                case 3:
                    comboBox2.SelectedIndex = 1;
                    comboBox3.SelectedIndex = 0;
                    textBox2.Text = "E1 10";
                    break;
                case 4:
                    comboBox2.SelectedIndex = 0;
                    comboBox3.SelectedIndex = 1;
                    textBox2.Text = "A0 00 00 03 96 56 43 41 03 F0 15 40 00 00 00 0B";
                    break;
                case 5:
                    comboBox2.SelectedIndex = 1;
                    comboBox3.SelectedIndex = 0;
                    textBox2.Text = "DF 01";
                    break;
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            System.Diagnostics.Debug.WriteLine("[Log] 'Select Existing Card Application' button clicked.");
            byte[] databuf = new byte[20];
            byte[] sendbuf = new byte[128];
            byte[] revbuf = new byte[128];
            byte[] revbuflen = new byte[4];
            byte datalen = 0;

            switch (comboBox1.SelectedIndex)
            {
                case 0:
                    datalen = 7;
                    break;
                case 1:
                    datalen = 2;
                    break;
                case 2:
                    datalen = 7;
                    break;
                case 3:
                    datalen = 2;
                    break;
                case 4:
                    datalen = 16;
                    break;
                case 5:
                    datalen = 2;
                    break;
            }

            if (checkhexstr(textBox2.Text.Trim(), datalen, databuf) == false)
            {
                MessageBox.Show("Hex target ID input error, please enter " + datalen.ToString("D") + " bytes of target ID!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            sendbuf[0] = 0x00;
            sendbuf[1] = 0xA4;

            //'00h Select MF, DF or EF, by file identifier
            //'01h Select child DF
            //'02h Select EF under the current DF, by file identifier
            //'03h Select parent DF of the current DFP
            //'04h Select by DF name
            if (comboBox2.SelectedIndex == 0)
            {
                sendbuf[2] = 0x04;
            }
            else { sendbuf[2] = 0x00; }

            //'00h Return FCI template: data stored in the file with ID 1Fh should be returned
            //'0Ch No response data: no FCI should be returned
            if (comboBox3.SelectedIndex == 0)
            {
                sendbuf[3] = 0x00;
            }
            else { sendbuf[3] = 0x0C; }

            sendbuf[4] = datalen;
            for (int i = 0; i < datalen; i++)
            {
                sendbuf[i + 5] = databuf[i];
            }

            byte status = cpuisoapdu(sendbuf, Convert.ToByte(datalen + 6), revbuf, revbuflen);
            if (status == 0 || status == 55)
            {
                Int32 j = 0;
                string strls = "";
                while (j < revbuflen[0])
                {
                    strls = strls + revbuf[j].ToString("X2");
                    j++;
                }

                if (status == 0)
                {
                    MessageBox.Show("Select card app return code: " + strls + ", Description: " + RetTextFromStr(strls), "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    MessageBox.Show("Select card app returned error code: " + status.ToString("D") + ", Description: remaining data not received, please send AA to continue receiving!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            else
            {
                if (status == 53)
                {
                    MessageBox.Show("Select card app returned error code: " + status.ToString("D") + ", Description: CPU card not responding. Please remove and replace the card, then click [Step 1: Activate Ntag 424].", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    MessageBox.Show("Select card app returned error code: " + status.ToString("D"), "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            System.Diagnostics.Debug.WriteLine("[Log] 'Step 1 Activate Ntag 424' button clicked.");
            byte status;  //'存放返回值
            byte[] mypiccserial = new byte[7];//'卡序列号            
            byte[] myparam = new byte[4];
            byte[] AtqaSak = new byte[3];
            byte[] myver = new byte[1];
            byte[] mycode = new byte[1];
            string cardhohex = "";
            string parastr = "";
            string verstr = "";
            string codestr = "";
            int i;

            status = cpurequest1(mypiccserial, myparam, myver, mycode, AtqaSak);
            if (status == 0 || status == 52)
            {
                pcdbeep(20);
                if (AtqaSak[0] / 64 > 0)
                {
                    for (i = 0; i < 7; i++) { cardhohex = cardhohex + mypiccserial[i].ToString("X2"); }
                    for (i = 0; i < 4; i++) { parastr = parastr + myparam[i].ToString("X2"); }
                    verstr = myver[0].ToString("X2");
                    codestr = mycode[0].ToString("X2");
                    textBox1.Text = cardhohex;
                    MessageBox.Show("Desfire card activation successful, you can proceed with Step 2 for debugging.\r\n" + "Hex Card No.: " + cardhohex + "\r\nParameters: " + parastr + "\r\nVersion Info: " + verstr + "\r\nManufacturer Code (Fudan=90): " + codestr, "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    for (i = 0; i < 4; i++) { cardhohex = cardhohex + mypiccserial[i].ToString("X2"); }
                    for (i = 0; i < 4; i++) { parastr = parastr + myparam[i].ToString("X2"); }
                    verstr = myver[0].ToString("X2");
                    codestr = mycode[0].ToString("X2");
                    textBox1.Text = cardhohex;
                    MessageBox.Show("Fm1208 CPU card activation successful, you can proceed with Step 2 for debugging.\r\n" + "Hex Card No.: " + cardhohex + "\r\nParameters: " + parastr + "\r\nVersion Info: " + verstr + "\r\nManufacturer Code (Fudan=90): " + codestr, "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            else
            {
                MessageDispInfo(status);
            }
        }

        private void button18_Click(object sender, EventArgs e)
        {
            System.Diagnostics.Debug.WriteLine("[Log] 'Key Authentication' button clicked.");
            byte[] authkeybuf = new byte[24];
            byte[] retsw = new byte[2];
            string retstr;
            int keylen = 16;

            if (checkhexstr(textBox6.Text.Trim(), keylen, authkeybuf) == false)
            {
                MessageBox.Show("Hex auth key input error, please enter " + keylen.ToString("D") + " bytes of hex auth key!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            byte status = desfireauthkeyev2(authkeybuf, Convert.ToByte(keyid.Value), Convert.ToByte(comboBox14.SelectedIndex), retsw);
            retstr = retsw[0].ToString("X2") + retsw[1].ToString("X2");

            if (status > 0)
            {
                MessageBox.Show("Key authentication returned error: " + status.ToString("D") + ", card return code: " + retstr + ", Description: " + RetTextFromStr(retstr), "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            else
            {
                MessageBox.Show("Key authentication, card return code: " + retstr + ", Description: " + RetTextFromStr(retstr), "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private void button6_Click(object sender, EventArgs e)
        {
            byte[] newkeybuf = new byte[24];
            byte[] oldkeybuf = new byte[24];
            byte[] retsw = new byte[2];
            string retstr;
            int keylen = 16;

            if (checkhexstr(textBox3.Text.Trim(), keylen, newkeybuf) == false)
            {
                MessageBox.Show("Hex new key input error, please enter " + keylen.ToString("D") + " bytes of hex new key!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            if (checkhexstr(textBox6.Text.Trim(), keylen, oldkeybuf) == false)
            {
                MessageBox.Show("Hex old key input error, please enter " + keylen.ToString("D") + " bytes of hex old key!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }


            byte status = ntagchangkey(newkeybuf, Convert.ToByte(editkeyid.Value), 1, oldkeybuf, retsw);
            retstr = retsw[0].ToString("X2") + retsw[1].ToString("X2");

            if (status > 0)
            {
                MessageBox.Show("Change key returned error: " + status.ToString("D") + ", card return code: " + retstr + ", Description: " + RetTextFromStr(retstr), "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            else
            {
                if (retstr == "91AE")
                {
                    MessageBox.Show("Change key returned error: " + status.ToString("D") + ", card return code: " + retstr + ", Description: Change key command disabled, key not authenticated, or key incorrect. Please authenticate with Key 0 first!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                else
                {
                    MessageBox.Show("Change key operation, card return code: " + retstr + ", Description: " + RetTextFromStr(retstr), "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
        }

        private void button3_Click(object sender, EventArgs e)
        {
            if (MessageBox.Show("This function has been tested and proven effective. To prevent irreversible random UID changes during testing, this function is currently disabled. Modify the source code at your own risk!", "SEVERE WARNING", MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK) { 
            }
            return;
            
            byte[] settingsbuf = new byte[10];      //最大为10个字节
            byte[] retsw = new byte[2];

            settingsbuf[0]=0x00;        //0为固定UID，2为动态UID，特别警告，改为2后卡将会锁死这个序设定值，再也不能改回固定UID
            byte status = ntagsetconfiguration(0, settingsbuf, 1, retsw);
            string retstr = retsw[0].ToString("X2") + retsw[1].ToString("X2");
            if (status > 0)
            {
                MessageBox.Show("Change config returned error: " + status.ToString("D") + ", card return code: " + retstr + ", Description: " + RetTextFromStr(retstr), "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            else
            {
                if (retstr == "9100")
                {
                    pcdbeep(20);
                    MessageBox.Show("Configuration changed successfully!" , "Info", MessageBoxButtons.OK, MessageBoxIcon.Information );
                }
                else
                {
                    if (retstr == "91AE")
                    {
                        MessageBox.Show("Change config, card return code: " + retstr + ", Description: Change to random UID command disabled, key not authenticated, or key incorrect. Please authenticate with the correct key first!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                    else
                    {
                        MessageBox.Show("Change config, card return code: " + retstr + ", Description: " + RetTextFromStr(retstr), "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
            }
        }

        private void button5_Click(object sender, EventArgs e)
        {
            textBox4.Text = "Baidu";
            comboBox4.SelectedIndex = 1;
            textBox5.Text = "baidu.com?uid=00000000000000000000000000000000";

            comboBox7.SelectedIndex = 0;
            comboBox8.SelectedIndex = 5;
            comboBox9.SelectedIndex = 5;
            comboBox10.SelectedIndex = 5;
            comboBox11.SelectedIndex = 0;

            checkBox_SDM.Checked = true;
            checkBox_UID.Checked = true;
            checkBox_CounterMirror.Checked = false;
            checkBox_CounterLimit.Checked = false;
            checkBox_SDMNCF.Checked = false;

            comboBox_SdmPower.SelectedIndex = 0;
            comboBox_cmackey.SelectedIndex = 5;
            comboBox_counterkey.SelectedIndex = 6;
            
            numericUpDown1.Value = 0;
            numericUpDown2.Value = 0;
            numericUpDown3.Value = 26;
            numericUpDown4.Value = 0;
            numericUpDown5.Value = 0;
            numericUpDown6.Value = 0;
            numericUpDown7.Value = 0;
            numericUpDown8.Value = 0;

        }

        private void button9_Click(object sender, EventArgs e)
        {
            textBox4.Text = "Baidu";
            comboBox4.SelectedIndex = 1;
            textBox5.Text = "baidu.com?uid=00000000000000x000000";

            comboBox7.SelectedIndex = 0;
            comboBox8.SelectedIndex = 5;
            comboBox9.SelectedIndex = 5;
            comboBox10.SelectedIndex = 5;
            comboBox11.SelectedIndex = 0;

            checkBox_SDM.Checked = true;
            checkBox_UID.Checked = true;
            checkBox_CounterMirror.Checked = true;
            checkBox_CounterLimit.Checked = false;
            checkBox_SDMNCF.Checked = false;
            
            comboBox_SdmPower.SelectedIndex = 5;
            comboBox_cmackey.SelectedIndex = 5;
            comboBox_counterkey.SelectedIndex = 5;

            numericUpDown1.Value = 26;
            numericUpDown2.Value = 0;
            numericUpDown3.Value = 0;
            numericUpDown4.Value = 0;
            numericUpDown5.Value = 41;
            numericUpDown6.Value = 0;
            numericUpDown7.Value = 0;
            numericUpDown8.Value = 0;

        }

        private void button10_Click(object sender, EventArgs e)
        {
            textBox4.Text = "";
            comboBox4.SelectedIndex = 1;
            textBox5.Text = "baidu.com?picc_data=00000000000000000000000000000000&e=12345678901234560000000000000000&cmac=0000000000000000";

            comboBox7.SelectedIndex = 0;
            comboBox8.SelectedIndex = 5;
            comboBox9.SelectedIndex = 5;
            comboBox10.SelectedIndex = 5;
            comboBox11.SelectedIndex = 0;

            checkBox_SDM.Checked = true;
            checkBox_UID.Checked = true;
            checkBox_CounterMirror.Checked = true;
            checkBox_CounterLimit.Checked = false;
            checkBox_SDMNCF.Checked = true;

            comboBox_SdmPower.SelectedIndex = 0;
            comboBox_cmackey.SelectedIndex = 0;
            comboBox_counterkey.SelectedIndex = 0;

            numericUpDown1.Value = 0;
            numericUpDown2.Value = 62;
            numericUpDown3.Value = 27;
            numericUpDown4.Value = 100;
            numericUpDown5.Value = 0;        
            numericUpDown6.Value = 0;            
            numericUpDown7.Value = 62;
            numericUpDown8.Value = 32;
            
            
        }

        private void button11_Click(object sender, EventArgs e)
        {
            System.Diagnostics.Debug.WriteLine("[Log] 'Write URI to Card' button clicked.");
            byte myctrlword=0x00;
            byte[] picckey = new byte[200];     //需要认证的密码

            if (checkBox6.Checked)      //AES-128密文+MAC模式
            {
                byte[] keybuff = new byte[200];
                if (checkhexstr(textBox8.Text.Trim(), 16, keybuff) == false)
                {
                    MessageBox.Show("Hex auth key input error, please enter 16 bytes of auth key!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    textBox8.Select();
                    return;
                }

                switch (comboBox13.SelectedIndex)
                {
                    case 0:
                        myctrlword = 0x40;
                        break;
                    case 1:
                        myctrlword = 0x41;
                        break;
                    case 2:
                        myctrlword = 0x43;
                        break;
                }

                picckey[0] = 4;     //AES,用71指令认证
                picckey[1] =(byte) numericUpDown_keyid.Value ;
                for (int j = 0; j < 16; j++)
                {
                    picckey[j + 2] = keybuff[j];
                }                
            }

            string languagecodestr = "en";  //语言编码，英文为en,中文为zh
            int languagecodestrlen = languagecodestr.Length;

            string titlestr = textBox4.Text.Trim(); //标题
            int titlestrlen = System.Text.Encoding.GetEncoding(936).GetBytes(titlestr).Length; //标题长度

            int uriheaderindex = comboBox4.SelectedIndex;   //前缀

            string uristr = textBox5.Text.Trim();   //uri
            int uristrlen = System.Text.Encoding.GetEncoding(936).GetBytes(uristr).Length; //uri长度

            tagbuf_forumtype4_clear(); //清空标签数据缓冲
            byte status = tagbuf_adduri(languagecodestr, languagecodestrlen, titlestr, titlestrlen, uriheaderindex, uristr, uristrlen); //可以用此方法写入多条记录
            if (status > 0)
            {
                MessageBox.Show("Error adding to write buffer, error code: " + status.ToString("D") , "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            byte[] mypiccserial = new byte[7];
            byte[] mypiccseriallen = new byte[1];
            status = forumtype4_write_ndeftag(myctrlword, mypiccserial, mypiccseriallen, picckey);
            if (status == 0)
            {
                pcdbeep(38);
                string carduid = "ForumType4UID：";
                for (int i = 0; i < mypiccseriallen[0]; i++)
                {
                    carduid = carduid + mypiccserial[i].ToString("X02");
                }
                MessageBox.Show(carduid + ", URI written to card successfully!!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else { MessageDispInfo(status); }
        }

        private void textBox5_TextChanged(object sender, EventArgs e)
        {
            GetMousePosition();
        }

        private void textBox5_MouseUp(object sender, MouseEventArgs e)
        {
            GetMousePosition();
        }


        private void GetMousePosition()
        {
            int i = 7 + textBox5.SelectionStart;
            if (textBox4.Text.Trim().Length > 0)
            {
                i = i + 5;
            }
            textBox7.Text = i.ToString();
        }

        private void button12_Click(object sender, EventArgs e)
        {
            byte myctrlword = 0x00;
            byte[] picckey = new byte[200];     //需要认证的密码

            if (checkBox6.Checked)              //AES-128密文+MAC模式
            {
                byte[] keybuff = new byte[200];
                if (checkhexstr(textBox8.Text.Trim(), 16, keybuff) == false)
                {
                    MessageBox.Show("Hex auth key input error, please enter 16 bytes of auth key!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    textBox8.Select();
                    return;
                }

                switch (comboBox13.SelectedIndex)
                {
                    case 0:
                        myctrlword = 0x40;
                        break;
                    case 1:
                        myctrlword = 0x41;   //bit1-0为1表示通信模式为MAC，bit1-0为3表示通信模式为密文+MAC模式
                        break;
                    case 2:
                        myctrlword = 0x43;  //bit1-0为1表示通信模式为MAC，bit1-0为3表示通信模式为密文+MAC模式
                        break;
                }

                picckey[0] = 4;     //AES,用71指令认证
                picckey[1] = (byte)numericUpDown_keyid.Value;
                for (int j = 0; j < 16; j++)
                {
                    picckey[j + 2] = keybuff[j];
                }
            }

            if (checkBox1.Checked)  //解析镜像
            {
                byte[] keybuff = new byte[200];
                if (checkhexstr(textBox10.Text.Trim(), 16, keybuff) == false)
                {
                    MessageBox.Show("Hex SDM metadata read key input error, please enter 16 bytes of correct verification key!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    textBox10.Select();
                    return;
                }
                for (int j = 0; j < 16; j++)
                {
                    picckey[j + 18] = keybuff[j];
                }

                if (checkhexstr(textBox11.Text.Trim(), 16, keybuff) == false)
                {
                    MessageBox.Show("Hex CMAC verification key input error, please enter 16 bytes of correct CMAC key!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    textBox11.Select();
                    return;
                }
                for (int j = 0; j < 16; j++)
                {
                    picckey[j + 34] = keybuff[j];
                }
                myctrlword = (byte)(myctrlword + 4);    //bit2为1表示把动态镜像信息解析出来放到缓冲
            }

            tagbuf_forumtype4_clear(); //清空标签数据缓冲

            byte[] mypiccserial = new byte[7];
            byte[] mypiccseriallen = new byte[1];
            byte status = forumtype4_read_ndeftag(myctrlword, mypiccserial, mypiccseriallen, picckey);
            if (status == 0 || status == 93)
            {
                pcdbeep(38);
                string carduid = "UID：";
                for (int i = 0; i < mypiccseriallen[0]; i++)
                {
                    carduid = carduid + mypiccserial[i].ToString("X02");
                }

                byte[] revstrlen = new byte[1];
                byte[] recordnumber = new byte[1];
                byte[] mypiccdata = new byte[2048];
                tagbuf_read(mypiccdata, revstrlen, recordnumber);
                string ndefstr = Encoding.Default.GetString(mypiccdata);
                textBox12.Text = ndefstr;
                //Clipboard.Clear();
                //Clipboard.SetDataObject(ndefstr);
                if (status == 0)
                {
                    MessageBox.Show(carduid + " Read card successful!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    MessageBox.Show(carduid + " Line protection MAC comparison error!" , "Info", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
            else { MessageDispInfo(status); }

        }

        private void textBox4_TextChanged(object sender, EventArgs e)
        {
            GetMousePosition();
        }

        private void button14_Click(object sender, EventArgs e)
        {
            System.Diagnostics.Debug.WriteLine("[Log] 'Modify Card Configuration' button clicked.");
            byte[] settingsbuf = new byte[32];      //卡数据缓冲：1+2+1+2+3*8=30
            byte[] retsw = new byte[2];             //返回值

            switch (comboBox7.SelectedIndex)
            {
                case 0:
                    settingsbuf[0] = 0;   //明文
                    break;
                case 1:
                    settingsbuf[0] = 1;   //MAC保护
                    break;
                default:
                    settingsbuf[0] = 3;     //密文 MAC保护
                    break;
            }

            if (checkBox_SDM.Checked) { settingsbuf[0] = (byte)(settingsbuf[0] + 0x40); }   //启用SDM镜像

            //文件访问权限
            if (comboBox11.SelectedIndex < 5)    
            {
                settingsbuf[1] = (byte)comboBox11.SelectedIndex;        //更改指令 需要先认证的密码
            } 
            else 
            {
                if (comboBox11.SelectedIndex == 5)
                {
                    settingsbuf[1] = 0x0e;     //无需密码，直接用明文
                }
                else
                {
                    settingsbuf[1] = 0x0f;    //禁止该指令
                }
            }


            if (comboBox10.SelectedIndex < 5)    
            {
                settingsbuf[1] = (byte)(settingsbuf[1] + comboBox10.SelectedIndex * 16);        //读写指令 需要先认证的密码
            }
            else
            {
                if (comboBox10.SelectedIndex == 5)
                {
                    settingsbuf[1] =(byte)(settingsbuf[1]+ 0xe0);     //无需密码，直接用明文
                }
                else
                {
                    settingsbuf[1] =(byte)(settingsbuf[1] + 0xf0);    //禁止该指令
                }
            }

            if (comboBox9.SelectedIndex < 5)    
            {
                settingsbuf[2] = (byte)comboBox9.SelectedIndex;        //只写指令 需要先认证的密码
            }
            else
            {
                if (comboBox9.SelectedIndex == 5)
                {
                    settingsbuf[2] = 0x0e;     //无需密码，直接用明文
                }
                else
                {
                    settingsbuf[2] = 0x0f;    //禁止该指令
                }
            }

            if (comboBox8.SelectedIndex < 5)
            {
                settingsbuf[2] = (byte)(settingsbuf[2] + comboBox8.SelectedIndex * 16);        //只读指令 需要先认证的密码
            }
            else
            {
                if (comboBox8.SelectedIndex == 5)
                {
                    settingsbuf[2] = (byte)(settingsbuf[2] + 0xe0);     //无需密码，直接用明文
                }
                else
                {
                    settingsbuf[2] =(byte)(settingsbuf[2] +  0xf0);    //禁止该指令
                }
            }

            int j = 3;

            if ((settingsbuf[0] & 0x40) > 0)        //已经启用SDM镜像
            {
                //SDMOptions
                settingsbuf[3] = 1;     //Encoding mode默认为ASCII
                if (checkBox_UID.Checked)
                {
                    settingsbuf[3] = (byte)(settingsbuf[3] + 0x80);      //启用UID镜像
                }

                if (checkBox_CounterMirror.Checked)
                {
                    settingsbuf[3] = (byte)(settingsbuf[3] + 0x40);       //启用计数器镜像
                }

                if (checkBox_CounterLimit.Checked)
                {
                    settingsbuf[3] = (byte)(settingsbuf[3] + 0x20);       //计数器限额
                }

                if (checkBox_SDMNCF.Checked)
                {
                    settingsbuf[3] = (byte)(settingsbuf[3] + 0x10);       //SDMENCFileData
                }

                //SDMAccessRights
                settingsbuf[4] = 0xf0;      //Bit 7-4默认为F,暂无使用

                //计数器访问 需要先认证的密码 comboBox_counterkey
                if (comboBox_counterkey.SelectedIndex < 5)
                {
                    settingsbuf[4] = (byte)(settingsbuf[4] + comboBox_counterkey.SelectedIndex );        
                }
                else
                {
                    if (comboBox_counterkey.SelectedIndex == 5)
                    {
                        settingsbuf[4] =(byte)(settingsbuf[4] + 0x0e);     //无需密码，直接用明文
                    }
                    else
                    {
                        settingsbuf[4] = (byte)(settingsbuf[4] +0x0f);    //禁止该指令
                    }
                }

                //SDMMetaRead access right
                if (comboBox_SdmPower.SelectedIndex < 5)
                {
                    settingsbuf[5] = (byte)(comboBox_SdmPower.SelectedIndex * 16);        //只读指令 需要先认证的密码
                }
                else
                {
                    if (comboBox_SdmPower.SelectedIndex == 5)
                    {
                        settingsbuf[5] = 0xe0;     //无需密码，直接用明文
                    }
                    else
                    {
                        settingsbuf[5] = 0xf0;    //禁止该指令
                    }
                }

                j = j + 1;

                //SDMFileRead access right
                if (comboBox_cmackey.SelectedIndex < 5)
                {
                    settingsbuf[5] = (byte)(settingsbuf[5] + comboBox_cmackey.SelectedIndex);        //无需密码，直接用明文
                }
                else
                {
                    settingsbuf[5] = (byte)(settingsbuf[5] + 0x0f);    //禁止该指令
                }

                j = 6;
                byte[] bytearray = new byte[3];

                //-----------------------------------------------------------------------------------------------------
                if ((settingsbuf[5] & 0xf0) == 0xe0)
                {
                    if ((settingsbuf[3] & 0x80) > 0)   //UID镜像位置
                    {
                        if (Get3Byte((long)numericUpDown1.Value, bytearray))
                        {
                            settingsbuf[6] = bytearray[0];
                            settingsbuf[7] = bytearray[1];
                            settingsbuf[8] = bytearray[2];
                        }
                       
                        j = 9;
                    }

                    if ((settingsbuf[3] & 0x40) > 0)   //计数器镜像
                    {
                        if (Get3Byte((long)numericUpDown5.Value, bytearray))
                        {
                            settingsbuf[j] = bytearray[0];
                            settingsbuf[j+1] = bytearray[1];
                            settingsbuf[j+2] = bytearray[2];
                            j = j + 3;
                        }
                        else
                        {
                            MessageBox.Show("Counter data offset input error!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            return;
                        }                             
                    }
                }
                else
                {
                    if ((settingsbuf[5] & 0xf0) < 0x50)
                    {
                        if (Get3Byte((long)numericUpDown3.Value, bytearray))   //ENCPICCDataOffset(UID和随机数加密后的数据位置)
                        {
                            settingsbuf[6] = bytearray[0];
                            settingsbuf[7] = bytearray[1];
                            settingsbuf[8] = bytearray[2];
                            j = 9;
                        }
                        else
                        {
                            MessageBox.Show("PICCDataOffset input error!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            return;
                        }    
                    }
                }
                //----------------------------------------------------------------------------------------------------------------

                if ((settingsbuf[5] & 0x0f) != 0x0f)
                {
                    if (Get3Byte((long)numericUpDown2.Value, bytearray))    //SDMMACInputOffset
                    {
                        settingsbuf[j] = bytearray[0];
                        settingsbuf[j + 1] = bytearray[1];
                        settingsbuf[j + 2] = bytearray[2];
                        j = j + 3;
                    }
                    else
                    {
                        MessageBox.Show("SDMMACInputOffset input error!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }

                    if ((settingsbuf[3] & 0x10) > 0)  
                    {
                        if (Get3Byte((long)numericUpDown7.Value, bytearray))        //SDMENCOffset
                        {
                            settingsbuf[j] = bytearray[0];
                            settingsbuf[j + 1] = bytearray[1];
                            settingsbuf[j + 2] = bytearray[2];
                            j = j + 3;
                        }
                        else
                        {
                            MessageBox.Show("SDMENCOffset input error!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            return;
                        }

                        if (Get3Byte((long)numericUpDown8.Value, bytearray))        //SDMENCLength
                        {
                            settingsbuf[j] = bytearray[0];
                            settingsbuf[j + 1] = bytearray[1];
                            settingsbuf[j + 2] = bytearray[2];
                            j = j + 3;
                        }
                        else
                        {
                            MessageBox.Show("SDMENCLength input error!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            return;
                        }    
                    }

                    if (Get3Byte((long)numericUpDown4.Value, bytearray))        //SDMMACOffset
                    {
                        settingsbuf[j] = bytearray[0];
                        settingsbuf[j + 1] = bytearray[1];
                        settingsbuf[j + 2] = bytearray[2];
                        j = j + 3;
                    }
                    else
                    {
                        MessageBox.Show("SDMENCOffset input error!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                }

                if ((settingsbuf[3] & 0x20) > 0)  //计数器限额值
                {
                    if (Get3Byte((long)numericUpDown6.Value, bytearray))        //计数器限额值
                    {
                        settingsbuf[j] = bytearray[0];
                        settingsbuf[j + 1] = bytearray[1];
                        settingsbuf[j + 2] = bytearray[2];
                        j = j + 3;
                    }
                    else
                    {
                        MessageBox.Show("Counter limit value input error!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                }
            }

            //参数设定规则校验--------------------------------------------------------------------------------------
            if ((settingsbuf[3] & 0x40) > 0)        //已经启用SDM镜像
            {
                if ((settingsbuf[3] & 0xC0) == 0)
                {
                    MessageBox.Show("When SDM mirror is enabled, UID mirror or counter mirror must also be enabled!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                if ((settingsbuf[3] & 0x80) > 0)       //已经启用UID镜像
                {
                    if ((settingsbuf[5] & 0xF0) == 0xf0)
                    {
                        MessageBox.Show("When UID mirror is enabled, SDM metadata read access cannot be Disabled!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                }
                else
                {
                    if ((settingsbuf[5] & 0xF0) < 0xf0)
                    {
                        MessageBox.Show("When UID mirror is disabled, SDM metadata read access must be Disabled!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                }

                if ((settingsbuf[3] & 0x40) == 0)       //当不开启计数器镜像时
                {
                    if ((settingsbuf[4] & 0x0f) <0x0f)
                    {
                        MessageBox.Show("When counter mirror is disabled, SDM counter retrieval key must be set to Disabled!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                }

                int i;
                if ((settingsbuf[3] & 0x80) > 0 || (settingsbuf[5] & 0xF0) < 0x50)
                {
                    i = 9;      //存在UIDOffset或PICCDataOffset'
                }
                else
                {
                    i = 6;
                }

                if (settingsbuf[5] == 0xe0)
                {
                    i = i + 3;    //SDMReadCtrOffset存在
                }

                long SDMMACInputOffset=0;
                long SDMENCOffset=0;
                long SDMENCLength=0;
                long SDMMACOffset=0;
                if ((settingsbuf[5] & 0x0f) < 0x05)  //SDMFileRead access right
                {
                    SDMMACInputOffset = settingsbuf[i] + settingsbuf[i + 1] * 256 + settingsbuf[i + 2] * 65536;
                    i = i + 3;

                    if ((settingsbuf[3] & 0x10) > 0)        //SDMENCFileData
                    {
                        SDMENCOffset = settingsbuf[i] + settingsbuf[i + 1] * 256 + settingsbuf[i + 2] * 65536;
                        i = i + 3;

                        SDMENCLength = settingsbuf[i] + settingsbuf[i + 1] * 256 + settingsbuf[i + 2] * 65536;
                        i = i + 3;
                    }

                    SDMMACOffset = settingsbuf[i] + settingsbuf[i + 1] * 256 + settingsbuf[i + 2] * 65536;
                    i = i + 3;

                    if ((settingsbuf[3] & 0x10) > 0)        //SDMENCFileData
                    {
                        if (SDMENCOffset < SDMMACInputOffset){
                            MessageBox.Show("SDMENCOffset cannot be less than SDMMACInputOffset!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            return;
                        }

                        if (SDMENCLength < 32)
                        {
                            MessageBox.Show("SDMENCLength cannot be less than 32!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            return;
                        }

                        if (SDMMACOffset < (SDMENCOffset + SDMENCLength))
                        {
                            MessageBox.Show("SDMMACOffset cannot be less than (SDMENCOffset + SDMENCLength)!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            return;
                        }
                    }
                    else
                    {
                        if (SDMMACOffset < SDMMACInputOffset)
                        {
                            MessageBox.Show("SDMMACOffset cannot be less than SDMMACInputOffset!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            return;
                        }
                    }
                }
            }

            string strls = "";
            for (int i = 0; i < j; i++)
            {
                strls = strls + settingsbuf[i].ToString("X02");
            }
            textBox9.Text = strls;

            byte status = ntagchangefilesettings((byte)comboBox5.SelectedIndex, 2, settingsbuf, j, retsw);
            strls = retsw[0].ToString("X02") + retsw[1].ToString("X02");
            if (strls == "9100")
            {
                pcdbeep(50);
                MessageBox.Show("Configuration changed successfully!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                if (strls == "91AE")
                {
                    if (comboBox5.SelectedIndex == 1)
                    {
                        MessageBox.Show("Card returned error code: " + strls + ", change command disabled, key not authenticated, or key incorrect. Please authenticate with the correct key first!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                    else
                    {
                        MessageBox.Show("Card returned error code: " + strls + ", change command disabled or plaintext operation not supported. Please authenticate with the correct key and select 'Encrypted + MAC Protection' comm mode, then try again!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
                else
                {
                    MessageBox.Show("Card returned error code: " + strls + ", Description: " + RetTextFromStr(strls), "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }

        }

        private static bool Get3Byte(long number, byte[] bytearr)      //长整形转3字节数组
        {
            if (number>=0 && number < 16777215)
            {
                for (int i = 0; i < 3; i++)
                {
                    bytearr[i] = (byte)(number >> (i * 8)); // 右移并取低8位作为字节值
                }
                return true;
            }
            else
            {
                return false;
            }            
        }

        private void button13_Click(object sender, EventArgs e)
        {
            byte[] settingsbuf = new byte[32];
            byte[] revbuflen = new byte[2];
            byte[] retsw = new byte[2];
            byte status = ntagreadfilesettings((byte)comboBox5.SelectedIndex, 2, settingsbuf, revbuflen, retsw);            
            string strls = retsw[0].ToString("X02") + retsw[1].ToString("X02");
            if (status > 0)
            {
                MessageBox.Show("Function error: "+status.ToString()+", card returned error code: " + strls + ", Description: " + RetTextFromStr(strls), "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            if (strls == "9100")
            {
                if ((settingsbuf[1] & 0x03) == 1)  
                {
                    comboBox7.SelectedIndex = 1;           //MAC保护
                }
                else
                {
                    if ((settingsbuf[1] & 0x03) == 3)
                    {
                        comboBox7.SelectedIndex = 2;        //密文 MAC保护
                    }
                    else
                    {
                        comboBox7.SelectedIndex = 0;        //明文
                    }
                }

                int i = settingsbuf[2] % 16;    //更改指令 需要先认证的密码
                if (i >= 0x0e)
                {
                    comboBox11.SelectedIndex =5;
                }
                else
                {
                    if (i > 4)
                    {
                        comboBox11.SelectedIndex = 4;
                    }
                    else
                    {
                        comboBox11.SelectedIndex = i;
                    }
                }

                i = settingsbuf[2] / 16;        //读写指令 需要先认证的密码
                if (i == 0x0f)
                {
                    comboBox10.SelectedIndex = 6;
                }
                else
                {
                    if (i == 0x0e)
                    {
                        comboBox10.SelectedIndex = 5;
                    }
                    else
                    {
                        if (i > 4)
                        {
                            comboBox10.SelectedIndex = 4;
                        }
                        else
                        {
                            comboBox10.SelectedIndex = i;
                        }
                    }
                }

                i = settingsbuf[3] % 16;        //只写指令 需要先认证的密码
                if (i == 0x0f)
                {
                    comboBox9.SelectedIndex = 6;
                }
                else
                {
                    if (i == 0x0e)
                    {
                        comboBox9.SelectedIndex = 5;
                    }
                    else
                    {
                        if (i > 4)
                        {
                            comboBox9.SelectedIndex = 4;
                        }
                        else
                        {
                            comboBox9.SelectedIndex = i;
                        }
                    }
                }

                i = settingsbuf[3] / 16;        //只读指令 需要先认证的密码
                if (i == 0x0f)
                {
                    comboBox8.SelectedIndex = 6;
                }
                else
                {
                    if (i == 0x0e)
                    {
                        comboBox8.SelectedIndex = 5;
                    }
                    else
                    {
                        if (i > 4)
                        {
                            comboBox8.SelectedIndex = 4;
                        }
                        else
                        {
                            comboBox8.SelectedIndex = i;
                        }
                    }
                }

                //settingsbuf(4-5-6)为filesize
       
                //动态下标
                int j = 7;
                if ((settingsbuf[1] & 0x40)>0)
                {
                    checkBox_SDM.Checked = true;

                    //settingsbuf (7)为SDMOptions
                    if ((settingsbuf[j] & 0x80) > 0)
                    {
                        checkBox_UID.Checked = true;                 //启用UID镜像
                    }
                    else { checkBox_UID.Checked =false  ; }

                    if ((settingsbuf[j] & 0x40) > 0)
                    {
                        checkBox_CounterMirror.Checked = true;        //启用计数器镜像
                    }
                    else { checkBox_CounterMirror.Checked = false; }

                    if ((settingsbuf[j] & 0x20) > 0)
                    {
                        checkBox_CounterLimit.Checked = true;        //计数器限额
                    }
                    else { checkBox_CounterLimit.Checked = false; }

                    if ((settingsbuf[j] & 0x10) > 0)
                    {
                        checkBox_SDMNCF.Checked = true;              //SDMENCFileData
                    }
                    else { checkBox_SDMNCF.Checked = false; }

                    //'settingsbuf (j+1),settingsbuf (j+2)为SDMAccessRights        
                    //'计数器访问 需要先认证的密码 SDMCtrRet access right

                    i=settingsbuf[j + 1] % 16;
                    if (i == 0x0f)
                    {
                        comboBox_counterkey.SelectedIndex = 6;
                    }
                    else
                    {
                        if (i == 0x0e)
                        {
                            comboBox_counterkey.SelectedIndex = 5;
                        }
                        else
                        {
                            if (i > 4)
                            {
                                comboBox_counterkey.SelectedIndex = 4;
                            }
                            else
                            {
                                comboBox_counterkey.SelectedIndex = i;
                            }
                        }
                    }

                    //SDMMetaRead access right
                    i = settingsbuf[j + 2] / 16;
                    if (i == 0x0f)
                    {
                        comboBox_SdmPower.SelectedIndex = 6;
                    }
                    else
                    {
                        if (i == 0x0e)
                        {
                            comboBox_SdmPower.SelectedIndex = 5;
                        }
                        else
                        {
                            if (i > 4)
                            {
                                comboBox_SdmPower.SelectedIndex = 4;
                            }
                            else
                            {
                                comboBox_SdmPower.SelectedIndex = i;
                            }
                        }
                    }

                    //SDMFileRead access right
                    i = settingsbuf[j + 2] % 16;
                    if (i == 0x0f)
                    {
                        comboBox_cmackey.SelectedIndex = 5;
                    }
                    else
                    {
                        if (i > 4)
                        {
                            comboBox_cmackey.SelectedIndex = 4;
                        }
                        else
                        {
                            comboBox_cmackey.SelectedIndex = i;
                        }
                    }

                    j = j + 3;

                    //如果 SDMMetaRead access right = Eh
                    if (comboBox_SdmPower.SelectedIndex == 5)
                    {
                        if (checkBox_UID.Checked)   //if (SDMOptions[Bit 7]= 1b)
                        {
                            //UIDOffset
                            //UID镜像位置
                            long longi = settingsbuf[j] + settingsbuf[j + 1] * 256 + settingsbuf[j + 2] * 65536;
                            numericUpDown1.Value = longi;
                            j = j + 3;
                        }

                        if (checkBox_CounterMirror.Checked)   //if (SDMOptions[Bit 6] = 1b)
                        {
                            //SDMReadCtrOffset
                            //UID计数器镜像
                            long longi = settingsbuf[j] + settingsbuf[j + 1] * 256 + settingsbuf[j + 2] * 65536;
                            numericUpDown5.Value = longi;
                            j = j + 3;
                        }
                    }
                    else
                    {
                        if (comboBox_SdmPower.SelectedIndex < 5)  //ENCPICCDataOffset(UID和随机数加密后的数据位置)
                        {
                            long longi = settingsbuf[j] + settingsbuf[j + 1] * 256 + settingsbuf[j + 2] * 65536;
                            numericUpDown3.Value = longi;
                            j = j + 3;
                        }
                    }

                    if (comboBox_cmackey.SelectedIndex < 5)        //if SDMFileReadaccess right != Fh]
                    {
                        long longi = settingsbuf[j] + settingsbuf[j + 1] * 256 + settingsbuf[j + 2] * 65536;        //SDMMACInputOffset
                        numericUpDown2.Value = longi;
                        j = j + 3;

                        if (checkBox_SDMNCF.Checked)
                        {
                            longi = settingsbuf[j] + settingsbuf[j + 1] * 256 + settingsbuf[j + 2] * 65536;         //SDMENCOffset
                            numericUpDown7.Value = longi;
                            j = j + 3;

                            longi = settingsbuf[j] + settingsbuf[j + 1] * 256 + settingsbuf[j + 2] * 65536;         //SDMENCLength
                            numericUpDown8.Value = longi;
                            j = j + 3;
                        }

                        longi = settingsbuf[j] + settingsbuf[j + 1] * 256 + settingsbuf[j + 2] * 65536;             //SDMMACOffset
                        numericUpDown4.Value = longi;
                        j = j + 3;
                    }

                    if (checkBox_CounterLimit.Checked)
                    {
                        long longi = settingsbuf[j] + settingsbuf[j + 1] * 256 + settingsbuf[j + 2] * 65536;        //计数器限额值
                        numericUpDown6.Value = longi;
                    }
                }
                else
                {
                    checkBox_SDM.Checked = false;
                    checkBox_UID.Checked = false;
                    checkBox_CounterMirror.Checked = false;
                    checkBox_CounterLimit.Checked = false;
                    checkBox_SDMNCF.Checked = false;
                }

                j = 0;
                strls = "";
                int bufflen = BitConverter.ToInt16(revbuflen, 0);
                for (j = 0; j < bufflen; j++)
                {
                    strls = strls + settingsbuf[j].ToString("X02");
                }
                textBox9.Text = strls;

                pcdbeep(50);
                MessageBox.Show("Read card configuration successful!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                if (strls == "917E")
                {
                    MessageBox.Show("Instruction length error. If the previous operation was key authentication, this command must use Encrypted + MAC comm mode, otherwise use plaintext comm mode!" , "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                else
                {
                    MessageBox.Show("Card returned error code: " + strls + ", Description: " + RetTextFromStr(strls), "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);                     
                }
            }
        }

        private void Form1_FormClosed(object sender, FormClosedEventArgs e)
        {            
            writeINI("./syssetup.ini", "DefaultSetup", "textBox4", textBox4.Text);
            writeINI("./syssetup.ini", "DefaultSetup", "comboBox4", comboBox4.SelectedIndex.ToString());
            writeINI("./syssetup.ini", "DefaultSetup", "textBox5", textBox5.Text);

            writeINI("./syssetup.ini", "DefaultSetup", "comboBox7", comboBox7.SelectedIndex.ToString());
            writeINI("./syssetup.ini", "DefaultSetup", "comboBox8", comboBox8.SelectedIndex.ToString());
            writeINI("./syssetup.ini", "DefaultSetup", "comboBox9", comboBox9.SelectedIndex.ToString());
            writeINI("./syssetup.ini", "DefaultSetup", "comboBox10", comboBox10.SelectedIndex.ToString());
            writeINI("./syssetup.ini", "DefaultSetup", "comboBox11", comboBox11.SelectedIndex.ToString());

            if (checkBox6.Checked) 
            {
                writeINI("./syssetup.ini", "DefaultSetup", "checkBox6", "1");
            }
            else { writeINI("./syssetup.ini", "DefaultSetup", "checkBox6", "0"); }
            writeINI("./syssetup.ini", "DefaultSetup", "numericUpDown_keyid", numericUpDown_keyid.Value.ToString());
            writeINI("./syssetup.ini", "DefaultSetup", "textBox8", textBox8.Text);
            writeINI("./syssetup.ini", "DefaultSetup", "comboBox13", comboBox13.SelectedIndex.ToString());

            if (checkBox_SDM.Checked) 
            {
                writeINI("./syssetup.ini", "DefaultSetup", "checkBox_SDM", "1");
            }
            else { writeINI("./syssetup.ini", "DefaultSetup", "checkBox_SDM", "0"); }

            if (checkBox_UID.Checked)
            {
                writeINI("./syssetup.ini", "DefaultSetup", "checkBox_UID", "1");
            }
            else { writeINI("./syssetup.ini", "DefaultSetup", "checkBox_UID", "0"); }

            if (checkBox_CounterMirror.Checked)
            {
                writeINI("./syssetup.ini", "DefaultSetup", "checkBox_CounterMirror", "1");
            }
            else { writeINI("./syssetup.ini", "DefaultSetup", "checkBox_CounterMirror", "0"); }

            if (checkBox_CounterLimit.Checked)
            {
                writeINI("./syssetup.ini", "DefaultSetup", "checkBox_CounterLimit", "1");
            }
            else { writeINI("./syssetup.ini", "DefaultSetup", "checkBox_CounterLimit", "0"); }

            if (checkBox_SDMNCF.Checked)
            {
                writeINI("./syssetup.ini", "DefaultSetup", "checkBox_SDMNCF", "1");
            }
            else { writeINI("./syssetup.ini", "DefaultSetup", "checkBox_SDMNCF", "0"); }

            writeINI("./syssetup.ini", "DefaultSetup", "comboBox_SdmPower", comboBox_SdmPower.SelectedIndex.ToString());
            writeINI("./syssetup.ini", "DefaultSetup", "comboBox_cmackey", comboBox_cmackey.SelectedIndex.ToString());
            writeINI("./syssetup.ini", "DefaultSetup", "comboBox_counterkey", comboBox_counterkey.SelectedIndex.ToString());

            writeINI("./syssetup.ini", "DefaultSetup", "numericUpDown1", numericUpDown1.Value.ToString());
            writeINI("./syssetup.ini", "DefaultSetup", "numericUpDown2", numericUpDown2.Value.ToString());
            writeINI("./syssetup.ini", "DefaultSetup", "numericUpDown3", numericUpDown3.Value.ToString());
            writeINI("./syssetup.ini", "DefaultSetup", "numericUpDown4", numericUpDown4.Value.ToString());
            writeINI("./syssetup.ini", "DefaultSetup", "numericUpDown5", numericUpDown5.Value.ToString());
            writeINI("./syssetup.ini", "DefaultSetup", "numericUpDown6", numericUpDown6.Value.ToString());
            writeINI("./syssetup.ini", "DefaultSetup", "numericUpDown7", numericUpDown7.Value.ToString());
            writeINI("./syssetup.ini", "DefaultSetup", "numericUpDown8", numericUpDown8.Value.ToString());            
        }

        private void button15_Click(object sender, EventArgs e)
        {
            byte[] keybuff = new byte[200];
            if (checkhexstr(textBox8.Text.Trim(), 16, keybuff) == false)
            {
                MessageBox.Show("Hex auth key input error, please enter 16 bytes of auth key!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Error);
                textBox8.Select();
                return;
            }
            byte[] mypiccserial = new byte[16];
            byte[] mypiccseriallen = new byte[1];
            byte[] picckey = new byte[18];     //需要认证的密码

            picckey[0] = 4;     //AES,用71指令认证
            picckey[1] = (byte)numericUpDown_keyid.Value;
            for (int j = 0; j < 16; j++)
            {
                picckey[j + 2] = keybuff[j];
            }
            byte status = forumtype4getuid(mypiccserial, mypiccseriallen, picckey);
            if (status == 0)
            {
                pcdbeep(38);
                string carduid = "";
                for (int i = 0; i < mypiccseriallen[0]; i++)
                {
                    carduid = carduid + mypiccserial[i].ToString("X02");
                }
                MessageBox.Show("Real UID read successfully! Real UID: " + carduid, "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                MessageDispInfo(status);
            }
        }

        private void comboBox2_SelectedIndexChanged(object sender, EventArgs e)
        {

        }

        private void comboBox3_SelectedIndexChanged(object sender, EventArgs e)
        {

        }

        private void checkBox6_CheckedChanged(object sender, EventArgs e)
        {

        }



    }
}
