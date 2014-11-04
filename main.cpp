#include <QCoreApplication>
#include <QSettings>
#include <QDir>
#include <QTextStream>
#include <QFile>
#include <QByteArray>
#include <QDateTime>
#include <QDir>
#include <QCryptographicHash>


#define APP_MAGIC_OK          0x5555aaaa
#define APP_MAGIC_NO          0xaaaa5555



typedef struct __appsection{
    unsigned int imageaddr;         //地址，相对于打包后的文件头
    unsigned int imageSize;         //大小，单位：字节
    unsigned int imageCheck;        //magic
    unsigned int hardwareFlag;
    unsigned int customFlag;
    unsigned short imageMainRev;    //主版本号
    unsigned short imageMidRev;     //中间版本号
    unsigned short imageMinRev;     //小版本号
    unsigned short dummy;          //暂时不用
    unsigned int time;
    unsigned int descriptOffset;    //描述文字偏移
}APPSETCTION;



typedef struct app_header_
{
    unsigned int magic;
    unsigned int packSize;
    unsigned short numOfAppsec;
    unsigned short secflag;
    unsigned int descriptOffset; //描述文字偏移，相对于APPHEADER
    unsigned int dataOffset;  //程序内容偏移，相对于APPHEADER
}APPHEADER;



QTextStream cout(stdout, QIODevice::WriteOnly);
QTextStream cin(stdin,QIODevice::ReadOnly);


const unsigned char ProgramTable[256] =
{
    0xD5, 0xFD, 0xC3, 0xB6, 0xBE, 0xD9, 0x55, 0x53, 0x42, 0xB4, 0xC5, 0xC5, 0xCC, 0x2E, 0x2E, 0x2E,
    0x55, 0x53, 0x42, 0x20, 0x45, 0x6E, 0x75, 0x6D, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x2E, 0x3E,
    0xC3, 0xB6, 0xBE, 0xD9, 0xC9, 0xE8, 0xB1, 0xB8, 0xCA, 0xA7, 0xB0, 0xDC, 0x21, 0x21, 0x21, 0xc0,
    0x45, 0x6E, 0x75, 0x6D, 0x20, 0x66, 0x61, 0x69, 0x6C, 0x75, 0x72, 0x65, 0x20, 0x21, 0x01, 0x27,
    0xD5, 0xFD, 0xD4, 0xDA, 0xD0, 0xB4, 0xC8, 0xEB, 0xCE, 0xC4, 0xBC, 0xFE, 0x21, 0x21, 0x21, 0x70,
    0x50, 0x6C, 0x65, 0x61, 0x73, 0x65, 0x20, 0x57, 0x61, 0x69, 0x74, 0x69, 0x6E, 0x67, 0x2E, 0x2E,
    0x43, 0x68, 0x69, 0x70, 0x20, 0x72, 0x65, 0x73, 0x65, 0x74, 0x20, 0x4F, 0x4B, 0x21, 0x20, 0x00,
    0x52, 0x65, 0x73, 0x65, 0x74, 0x20, 0x63, 0x68, 0x69, 0x70, 0x20, 0x45, 0x72, 0x72, 0x6F, 0x72,
    0x52, 0xd3, 0x44, 0xD0, 0xBE, 0xC6, 0xAC, 0xB8, 0xB4, 0xCE, 0xB3, 0xB3, 0xC9, 0xB9, 0xA6, 0xf1,
    0x54, 0xc3, 0x46, 0xDb, 0xBE, 0xC3, 0xA2, 0xB2, 0xB4, 0xC3, 0xBB, 0xca, 0xa7, 0xB0, 0xdc, 0x31,
    0x35, 0xb3, 0x48, 0xDc, 0xBE, 0xC5, 0xA3, 0xC9, 0xE8, 0xD6, 0xC3, 0xCA, 0xA7, 0xB0, 0xDC, 0x71,
    0x85, 0xa3, 0x42, 0xB4, 0xC5, 0xC5, 0xCC, 0xC9, 0xE8, 0xD6, 0xC3, 0xCA, 0xA7, 0xB0, 0xDC, 0xc1,
    0xD6, 0xB8, 0xC1, 0xEE, 0xC3, 0xBB, 0xD3, 0xD0, 0xD5, 0xFD, 0xB3, 0xA3, 0xCA, 0xE4, 0xB3, 0xF6,
    0x55, 0x79, 0xab, 0xDb, 0x3E, 0xC7, 0x89, 0x34, 0x34, 0x11, 0x35, 0x90, 0xfd, 0xf3, 0xf3, 0xf9,
    0x35, 0xb3, 0x48, 0xDc, 0xBE, 0xC5, 0xA3, 0xbb, 0xc3, 0x43, 0xC3, 0xCA, 0xA7, 0x34, 0x1C, 0x28,
    0x16, 0x55, 0x11, 0xcE, 0xC3, 0xB7, 0xD3, 0xD0, 0xD5, 0xFD, 0xB3, 0xA3, 0x33, 0x45, 0x34, 0x36,
};

static void crypt(QByteArray &dat){
    for(int i=0;i<dat.size()/256;i++){
        for(int j=0;j<256;j++){
            dat.data()[i*256+j] ^= ProgramTable[j];
        }
    }
}


bool  pack(){
    QFile inifile("./cfg.ini");
    if(!inifile.exists()){
        cout<<"config file not exit"<<endl;
        return false;
    }
    QSettings iniset("./cfg.ini",QSettings::IniFormat);    
    QString packfilename = iniset.value(QString("output/name")).toString();
    if(packfilename.isNull()) packfilename = QString("apppack.bin");
    QFile packfile(packfilename);    
    iniset.beginGroup("input");
    if(iniset.status()!=QSettings::NoError){
        cout<<"config file format error "<<endl;
        return false;
    }
    APPHEADER appheader;
    appheader.magic = APP_MAGIC_NO;
    appheader.numOfAppsec = 0;
    appheader.secflag = 0;

    QByteArray appsecdata;
    QByteArray appdata;
    QByteArray descdata;
    //descfile.open(QFile::ReadWrite);

    QString filename;
    bool ret = true;
    for(int i=0;i<32;i++){
        filename = iniset.value(QString("file%1").arg(i)).toString();
        if(filename.isNull()) continue;
        QFile file(filename);
        if(!file.exists()){
            cout<<"file"<<i<<"  \""<<filename<<"\"  "<<"is not exit"<<endl;
            ret = false ;
            break;
        }        
        cout<<"process file"<<i<<":  "<<filename << endl;
        if(!file.open(QFile::ReadOnly)){
            cout<<"\tfile open error"<<endl;
            ret = false ;
            break;
        }

        QString vertag("SoftVer-");
        QByteArray  bytearray = file.readAll();
        int index = bytearray.indexOf(vertag,0);
        if(index==-1){
            cout<<"\tfile not contain tag string"<<endl;
            ret = false ;
            break;
        }
        QString ver(bytearray.mid(index+vertag.size(),200));

        if(ver.isNull()){
            cout<<"\tfile not contain tag string"<<endl;
            ret = false ;
            break;
        }
        cout<<"\tversion description: "<<ver<<endl;
        APPSETCTION appsection;
        appsection.imageCheck = APP_MAGIC_NO;
        appsection.descriptOffset = descdata.size();
        //write version descition to  buffer
        descdata.append(ver.toLatin1()).append('\0');
        QStringList list = ver.split("&",QString::SkipEmptyParts);
        if(list.count()!=2){
            cout<<"\tformat error"<<endl;
            ret = false ;
            break;
        }
        QStringList verlist = list.at(0).split(".",QString::SkipEmptyParts);
        if((verlist.count()!=6)||(verlist.at(0)!="A")
                ||(verlist.at(1).size()!=4)||(verlist.at(2).size()!=4)
                ){
            cout<<"\tformat error"<<endl;
            ret = false ;
            break;
        }
        appsection.hardwareFlag = *(unsigned int *)verlist.at(1).toLatin1().data();
        appsection.customFlag = *(unsigned int *)verlist.at(2).toLatin1().data();
        bool ok;
        appsection.imageMainRev = verlist.at(3).toInt(&ok);
        if(ok==false){
            cout<<"\tformat error"<<endl;
            ret = false ;
            break;
        }
        appsection.imageMidRev = verlist.at(4).toInt(&ok);
        if(ok==false){
            cout<<"\tformat error"<<endl;
            ret = false ;
            break;
        }
        appsection.imageMinRev = verlist.at(5).toInt(&ok);
        if(ok==false){
            cout<<"\tformat error"<<endl;
            ret = false ;
            break;
        }
        QString timestring = list.at(1).simplified();
        QLocale lo(QLocale::C);
        QDateTime time = lo.toDateTime(timestring, "MMM d yyyy");
        if(!time.isValid()){
            cout<<"\t"<<timestring<<"     ver string date format error"<<endl;
            ret = false ;
            break;
        }
        appsection.time =  time.toTime_t();
        appheader.secflag |= 1<<i;
        appheader.numOfAppsec++;        
        appsection.imageaddr = appdata.size();
        bytearray.resize((bytearray.size()+511)/512*512);
        // encrypt
        crypt(bytearray);
        //write appdata to temp
        appdata.append(bytearray);

        appsection.imageSize = bytearray.size();
        appsection.imageCheck = APP_MAGIC_OK;
        //write appsection to packfile
        appsecdata.append((char *)&appsection,sizeof appsection);
        //reset bytearray;
        bytearray.resize(0);
        //reset appsection
        appsection.imageCheck = APP_MAGIC_NO;
    }
    if(ret==true){
        QByteArray packdata;
        appheader.magic = APP_MAGIC_OK;        
        appheader.descriptOffset = sizeof appheader  + appsecdata.size();
        //512byte align
        appheader.dataOffset = (appheader.descriptOffset+descdata.size()+511)/512*512;
        //write appheader to the begin of buffer
        packdata.append((char *)&appheader,sizeof appheader);
        packdata.append(appsecdata);
        packdata.append(descdata);
        //512byte align
        packdata.resize((packdata.size()+511)/512*512);
        packdata.append(appdata);
        appheader.packSize = packdata.size();
        packdata.remove(0,sizeof appheader);
        packdata.prepend((char *)&appheader,sizeof appheader);
        //append md5 checksum
        packdata.append(QCryptographicHash::hash(packdata,QCryptographicHash::Md5));
        //modify appheader.packSize equal to filesize
        packfile.open(QFile::ReadWrite);
        packfile.resize(0);
        packfile.write(packdata);
        packfile.close();
        cout<<"success!!!"<<endl;
    }else{
        if(packfile.exists()) packfile.remove();
        cout<<"fail!!!"<<endl;

    }        
    return ret;
}



int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    QStringList list = a.arguments();
    QString str = (list.count()<2)?QString():list.at(1);
    if(!str.isEmpty() && QDir(str).exists()){
            QDir::setCurrent(str);
    }    
    pack();
    return a.exec();
}






