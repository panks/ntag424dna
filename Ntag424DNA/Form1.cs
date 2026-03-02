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
                    MessageBox.Show("操作成功!", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    break;
                case 8:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，未寻到卡，请将卡拿开卡后再放到感应区!", "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 23:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，驱动程序错误或尚未安装！", "示例提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 24:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，操作超时，一般是动态库没有反映！", "示例提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 25:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，发送字数不够！", "示例提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 26:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，发送的CRC错！", "示例提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 27:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，接收的字数不够！", "示例提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 28:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，接收的CRC错！", "示例提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 47:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，读文件失败，请检查通信模式是否正确！", "示例提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 50:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，RATS错误，厂家调试代码，用户不需理会!", "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 51:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，PPS错误，厂家调试代码，用户不需理会!", "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 52:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，已进入了14443-4协议状态，可进行CPU卡功能所有操作了!", "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 53:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，CPU卡功能通讯错误!", "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 54:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，数据不足，需要接着发送未完成的数据至卡上!", "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 55:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，发送ACK指令给卡，让卡接着发送数据回来!", "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 56:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，清空根目录失败!", "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 57:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，卡片不支持Forum_Type4协议，请先认证打勾选中“需要认证密码再写入”再试，如果还有此提示，可能该卡不是Forum_Type4_Tag卡!", "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 58:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，卡片初始化失败!", "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 59:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，分配的空间不足!", "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 60:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，本次操作的实体已存在!", "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 61:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，无足够空间!", "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 62:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，文件不存在!", "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 63:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，权限不足,有可能是用只读密码认证，导致无法更改读写密码或无法写文件!", "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 64:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，密码不存在，或密钥文件未创建!", "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 65:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，传送长度错误!", "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 66:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，Le错误，即接收的数据长度指定过大!", "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 67:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，功能不支持或卡中无MF 或卡片已锁定!", "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 68:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，密码认证错识次数过多，该密码已被锁死!", "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 86:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，更改后的密码长度必须和创建时的长度一致!", "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 87:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，应用目录不存在!", "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 88:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，应用文件不存在!", "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;                
                case 90:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，读取文件时返回的长度不足，数据可能不正确!", "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 91:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，一次读文件的长度不能超过255!", "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                case 92:
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，一次写文件的长度不能超过247!", "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
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
                    MessageBox.Show("错误代码：" + errno.ToString("D") + "，密码错误，剩余次数为" + Convert.ToString(errno - 70) + "，如果为0，该密码将锁死，无法再认证", "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    break;
                default:
                    MessageBox.Show("操作失败，返回错误代码！" + Convert.ToString(errno), "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
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
                    RetTextFromStr = "成功！";
                    pcdbeep(20);
                    break;
                case "9100":
                    RetTextFromStr = "成功！";
                    pcdbeep(20);
                    break;
                case "6281":
                    RetTextFromStr = "回送的数据可能错误！";
                    break;
                case "6283":
                    RetTextFromStr = "选择文件无效，文件或密钥校验错误";
                    break;
                case "6400":
                    RetTextFromStr = "状态标志未改变";
                    break;
                case "6581":
                    RetTextFromStr = "写 EEPROM 不成功！";
                    break;
                case "6700":
                    RetTextFromStr = "长度错误";
                    break;
                case "6900":
                    RetTextFromStr = "CLA 与线路保护要求不匹配";
                    break;
                case "6901":
                    RetTextFromStr = "无效的状态！";
                    break;
                case "6981":
                    RetTextFromStr = "命令与文件结构不相容";
                    break;
                case "6982":
                    RetTextFromStr = "不满足安全状态";
                    break;
                case "6983":
                    RetTextFromStr = "密钥被锁死！";
                    break;
                case "6984":
                    RetTextFromStr = "MAC格式不符合";
                    break;
                case "6985":
                    RetTextFromStr = "使用条件不满足";
                    break;
                case "6986":
                    RetTextFromStr = "请先选择文件！";
                    break;
                case "6987":
                    RetTextFromStr = "无安全报文";
                    break;
                case "6988":
                    RetTextFromStr = "安全报文数据项不正确";
                    break;
                case "6A80":
                    RetTextFromStr = "数据域参数错误！";
                    break;
                case "6A81":
                    RetTextFromStr = "功能不支持或卡中无MF 或卡片已锁定";
                    break;
                case "6A82":
                    RetTextFromStr = "文件未找到";
                    break;
                case "6A83":
                    RetTextFromStr = "记录未找到！";
                    break;
                case "6A84":
                    RetTextFromStr = "文件无足够空间";
                    break;
                case "6A86":
                    RetTextFromStr = "参数P1 P2 错";
                    break;
                case "6A88":
                    RetTextFromStr = "密钥未找到！";
                    break;
                case "6B00":
                    RetTextFromStr = "在达到Le/Lc 字节之前文件结束，偏移量错误";
                    break;
                case "6E00":
                    RetTextFromStr = "无效的CLA";
                    break;
                case "6F00":
                    RetTextFromStr = "数据无效！";
                    break;
                case "9302":
                    RetTextFromStr = "MAC 错误";
                    break;
                case "9303":
                    RetTextFromStr = "应用已被锁定";
                    break;
                case "9401":
                    RetTextFromStr = "金额不足！";
                    break;
                case "9403":
                    RetTextFromStr = "密钥未找到！";
                    break;
                case "9406":
                    RetTextFromStr = "所需的MAC 不可用！";
                    break;
                case "91AE":
                    RetTextFromStr = "认证失败，请检查命行的参数和前期计算是否错误！";
                    break;
                case "91CA":
                    RetTextFromStr = "上一个命令未完全完成！";
                    break;
                case "917E":
                    RetTextFromStr = "指令长度错误！";
                    break;
                case "9140":
                    RetTextFromStr = "当前目录或应用密钥不存在，请先选择正确的目录或应用！";
                    break;
                case "919D":
                    RetTextFromStr = "处于未验证密码的状态，该指令无法操作！";
                    break;
                case "911E":
                    RetTextFromStr = "MAC错误！";
                    break;
                case "91F0":
                    RetTextFromStr = "该文件号不存在！";
                    break;
                case "919E":
                    RetTextFromStr = "参数无效！";
                    break;
                case "91BE":
                    RetTextFromStr = "试图读取/写入的数据超出文件/记录的边界！";
                    break;
                case "91A0":
                    RetTextFromStr = "请求的 AID 不存在！";
                    break;
                default:
                    if (inputstr.Substring(0, 3) == "63C")
                    {
                        int i = Convert.ToInt16(inputstr.Substring(3, 1), 16);
                        if (i > 0)
                        {
                            RetTextFromStr = "再试 " + i.ToString("D") + " 次错误密码将锁定！";
                        }
                        else { RetTextFromStr = "密码已被锁定"; }
                    }
                    else
                    {
                        RetTextFromStr = "未知的异常";
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
                MessageBox.Show("设备的序列号为：" + devno[0].ToString("D3") + "-" + devno[1].ToString("D3") + "-" + devno[2].ToString("D3") + "-" + devno[3].ToString("D3"), "示例程序", MessageBoxButtons.OK, MessageBoxIcon.Information);
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
                MessageBox.Show("获取IC卡芯片型号操作，卡片返回代码：" + retstr + "\r\n型号：" + cardtypestr, "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
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
                MessageBox.Show("十六进制目标ID输入错误，请输入 " + datalen.ToString("D") + " 字节的目标ID！", "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
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
                    MessageBox.Show("选择卡内应用操作卡片返回代码：" + strls + "，说明：" + RetTextFromStr(strls), "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    MessageBox.Show("选择卡内应用操作卡片返回异常代码：" + status.ToString("D") + "，说明：还有剩余数据没接收完，请再发AA继续接收后面的数据！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            else
            {
                if (status == 53)
                {
                    MessageBox.Show("选择卡内应用操作卡片返回异常代码：" + status.ToString("D") + "，说明：已出现发送无线信息后CPU卡没响应，请重新拿开卡后再放到感应区，再重新点【第一步：CPU卡复位】。", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    MessageBox.Show("选择卡内应用操作卡片返回异常代码：" + status.ToString("D"), "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
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
                    MessageBox.Show("激活Desfire卡成功，可以接着重复操作第二步进行调试了。\r\n" + "16进制卡号：" + cardhohex + "\r\n参数：" + parastr + "\r\n版本信息：" + verstr + "\r\n厂商代码(复旦为90)：" + codestr, "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    for (i = 0; i < 4; i++) { cardhohex = cardhohex + mypiccserial[i].ToString("X2"); }
                    for (i = 0; i < 4; i++) { parastr = parastr + myparam[i].ToString("X2"); }
                    verstr = myver[0].ToString("X2");
                    codestr = mycode[0].ToString("X2");
                    textBox1.Text = cardhohex;
                    MessageBox.Show("激活Fm1208CPU卡成功，可以接着重复操作第二步进行调试了。\r\n" + "16进制卡号：" + cardhohex + "\r\n参数：" + parastr + "\r\n版本信息：" + verstr + "\r\n厂商代码(复旦为90)：" + codestr, "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            else
            {
                MessageDispInfo(status);
            }
        }

        private void button18_Click(object sender, EventArgs e)
        {
            byte[] authkeybuf = new byte[24];
            byte[] retsw = new byte[2];
            string retstr;
            int keylen = 16;

            if (checkhexstr(textBox6.Text.Trim(), keylen, authkeybuf) == false)
            {
                MessageBox.Show("十六进制认证密钥输入错误，请输入 " + keylen.ToString("D") + " 字节的16进制认证密钥！", "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            byte status = desfireauthkeyev2(authkeybuf, Convert.ToByte(keyid.Value), Convert.ToByte(comboBox14.SelectedIndex), retsw);
            retstr = retsw[0].ToString("X2") + retsw[1].ToString("X2");

            if (status > 0)
            {
                MessageBox.Show("认证密码操作返回异常：" + status.ToString("D") + "，卡片返回代码：" + retstr + "，说明：" + RetTextFromStr(retstr), "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            else
            {
                MessageBox.Show("认证密码操作，卡片返回代码：" + retstr + "，说明：" + RetTextFromStr(retstr), "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
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
                MessageBox.Show("十六进制新密钥输入错误，请输入 " + keylen.ToString("D") + " 字节的16进制新密钥！", "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            if (checkhexstr(textBox6.Text.Trim(), keylen, oldkeybuf) == false)
            {
                MessageBox.Show("十六进制旧密钥输入错误，请输入 " + keylen.ToString("D") + " 字节的16进制旧密钥！", "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }


            byte status = ntagchangkey(newkeybuf, Convert.ToByte(editkeyid.Value), 1, oldkeybuf, retsw);
            retstr = retsw[0].ToString("X2") + retsw[1].ToString("X2");

            if (status > 0)
            {
                MessageBox.Show("更改卡密钥操作返回异常：" + status.ToString("D") + "，卡片返回代码：" + retstr + "，说明：" + RetTextFromStr(retstr), "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            else
            {
                if (retstr == "91AE")
                {
                    MessageBox.Show("更改卡密钥操作返回异常：" + status.ToString("D") + "，卡片返回代码：" + retstr + "，说明：更改密码指令被禁止或密码未认证或密码不对，请先用0号密码认证后再试！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                else
                {
                    MessageBox.Show("更改卡密钥操作，卡片返回代码：" + retstr + "，说明：" + RetTextFromStr(retstr), "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
        }

        private void button3_Click(object sender, EventArgs e)
        {
            if (MessageBox.Show("此功能已经过测试证明有效,为防止测试时把卡改成动态UID后不可恢复,暂不开放此功能，如需更改，自行修改代码，后果自负！", "严重警告", MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK) { 
            }
            return;
            
            byte[] settingsbuf = new byte[10];      //最大为10个字节
            byte[] retsw = new byte[2];

            settingsbuf[0]=0x00;        //0为固定UID，2为动态UID，特别警告，改为2后卡将会锁死这个序设定值，再也不能改回固定UID
            byte status = ntagsetconfiguration(0, settingsbuf, 1, retsw);
            string retstr = retsw[0].ToString("X2") + retsw[1].ToString("X2");
            if (status > 0)
            {
                MessageBox.Show("更改卡操作操作返回异常：" + status.ToString("D") + "，卡片返回代码：" + retstr + "，说明：" + RetTextFromStr(retstr), "提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            else
            {
                if (retstr == "9100")
                {
                    pcdbeep(20);
                    MessageBox.Show("更改配置成功！" , "提示", MessageBoxButtons.OK, MessageBoxIcon.Information );
                }
                else
                {
                    if (retstr == "91AE")
                    {
                        MessageBox.Show("更改配置操作，卡片返回代码：" + retstr + "，说明：更改为随机UID指令被禁止或密码未认证或密码不对，请先用正确的密码号进行认证再试！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                    else
                    {
                        MessageBox.Show("更改配置操作，卡片返回代码：" + retstr + "，说明：" + RetTextFromStr(retstr), "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
            }
        }

        private void button5_Click(object sender, EventArgs e)
        {
            textBox4.Text = "百度";
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
            textBox4.Text = "百度";
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
            byte myctrlword=0x00;
            byte[] picckey = new byte[200];     //需要认证的密码

            if (checkBox6.Checked)      //AES-128密文+MAC模式
            {
                byte[] keybuff = new byte[200];
                if (checkhexstr(textBox8.Text.Trim(), 16, keybuff) == false)
                {
                    MessageBox.Show("十六进制认证密钥输入错误，请输入16字节认证密钥！", "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
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
                MessageBox.Show("将写卡信息加入写卡缓冲时返回错误代码：" + status.ToString("D") , "示例提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
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
                MessageBox.Show(carduid + "，URI网址写入成功！！", "示例提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
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
                    MessageBox.Show("十六进制认证密钥输入错误，请输入16字节认证密钥！", "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
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
                    MessageBox.Show("十六进制SDM元数据读取验证密码输入错误，请输入16字节正确的验证密钥！", "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    textBox10.Select();
                    return;
                }
                for (int j = 0; j < 16; j++)
                {
                    picckey[j + 18] = keybuff[j];
                }

                if (checkhexstr(textBox11.Text.Trim(), 16, keybuff) == false)
                {
                    MessageBox.Show("十六进制CMAC验证密码输入错误，请输入16字节正确的CMAC验证密钥！", "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
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
                    MessageBox.Show(carduid + " 读卡成功！", "示例提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    MessageBox.Show(carduid + " 返回的线路保护MAC对比错误！" , "示例提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
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
                            MessageBox.Show("计数器数据位置输入错误！", "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
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
                            MessageBox.Show("PICCDataOffset输入错误！", "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
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
                        MessageBox.Show("SDMMACInputOffset输入错误！", "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
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
                            MessageBox.Show("SDMENCOffset输入错误！", "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
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
                            MessageBox.Show("SDMENCLength输入错误！", "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
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
                        MessageBox.Show("SDMENCOffset输入错误！", "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
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
                        MessageBox.Show("计数器限额值输入错误！", "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                }
            }

            //参数设定规则校验--------------------------------------------------------------------------------------
            if ((settingsbuf[3] & 0x40) > 0)        //已经启用SDM镜像
            {
                if ((settingsbuf[3] & 0xC0) == 0)
                {
                    MessageBox.Show("当开启SDM镜像时，必须开启UID镜像或计数器镜像！", "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                if ((settingsbuf[3] & 0x80) > 0)       //已经启用UID镜像
                {
                    if ((settingsbuf[5] & 0xF0) == 0xf0)
                    {
                        MessageBox.Show("当启用UID镜像时，SDM元数据读取访问权限不能为禁止！", "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                }
                else
                {
                    if ((settingsbuf[5] & 0xF0) < 0xf0)
                    {
                        MessageBox.Show("当不开启UID镜像时，SDM元数据读取访问权限只能为禁止！", "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                }

                if ((settingsbuf[3] & 0x40) == 0)       //当不开启计数器镜像时
                {
                    if ((settingsbuf[4] & 0x0f) <0x0f)
                    {
                        MessageBox.Show("当不开启计数器镜像时，SDM计数器检索密钥只能为禁止！", "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
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
                            MessageBox.Show("SDMENCOffset不能小于SDMMACInputOffset！", "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            return;
                        }

                        if (SDMENCLength < 32)
                        {
                            MessageBox.Show("SDMENCLength不能小于32！", "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            return;
                        }

                        if (SDMMACOffset < (SDMENCOffset + SDMENCLength))
                        {
                            MessageBox.Show("SDMMACOffset不能小于(SDMENCOffset + SDMENCLength)！", "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            return;
                        }
                    }
                    else
                    {
                        if (SDMMACOffset < SDMMACInputOffset)
                        {
                            MessageBox.Show("SDMMACOffset不能小于SDMMACInputOffset！", "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
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
                MessageBox.Show("更改配置成功！", "示例提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                if (strls == "91AE")
                {
                    if (comboBox5.SelectedIndex == 1)
                    {
                        MessageBox.Show("卡片返回错误代码：" + strls + "，更改指令被禁止或密码未认证或密码不对，请先用正确的密码号进行认证再试！", "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                    else
                    {
                        MessageBox.Show("卡片返回错误代码：" + strls + "，更改指令被禁止或不支持明文操作，请先用正确的密码号进行认证并且选择“密文+MAC保护的通信模式”再试！", "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
                else
                {
                    MessageBox.Show("卡片返回错误代码：" + strls + "说明：" + RetTextFromStr(strls), "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
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
                MessageBox.Show("函数异常："+status.ToString()+",卡片返回错误代码：" + strls + "说明：" + RetTextFromStr(strls), "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
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
                MessageBox.Show("读取卡配置信息成功！", "示例提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                if (strls == "917E")
                {
                    MessageBox.Show("指令长度错误，如果上一条操作为密码认证，本次指令必需用密文+MAC保护的通信模式，否则用明文的通信模式！" , "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                else
                {
                    MessageBox.Show("卡片返回错误代码：" + strls + "说明：" + RetTextFromStr(strls), "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);                     
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
                MessageBox.Show("十六进制认证密钥输入错误，请输入16字节认证密钥！", "警告", MessageBoxButtons.OK, MessageBoxIcon.Error);
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
                MessageBox.Show("读真实UID卡号成功！真实UID卡号：" + carduid, "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
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
