#!/bin/bash
echo "                       "
echo "( what are you doing? )"
echo  ---------------------
echo "      o   ^__^ "
echo "       o  (oo)\_______"
echo "          (__)\       )\/\ "
echo "              ||----w |    "  
echo "              ||     ||    "
echo 
echo "...."中间件日志分析脚本v2.0"..."
echo ------------------------------------------------------------
echo "自动分析中间件日志，并将日志中存在的SQL注入、XSS脚本攻击等攻击行为筛选出来"
echo "本脚本目前仅支持IIS、apache、weblogic中间件"
echo "新加入了针对getshell、敏感文件、以及LFI文件包含攻击的HTTP响应码200和500的分析"
echo "执行脚本之前，请将要分析的日志拷贝到/usr/目录下"
echo ----------------------按回车开始分析---------------------------
read key
file=/usr/nmgxy/
if [ -e "$file" ];then 
echo "日志目录存在，跳过创建过程，该操作会清空/usr/nmgxy/目录下所有数据"
echo "按回车键开始清空数据，结束请点击Ctrl+c"
read key
rm -r /usr/nmgxy/*
mkdir -p /usr/nmgxy/LFI/ /usr/nmgxy/exp/ /usr/nmgxy/sql/ /usr/nmgxy/scan/ /usr/nmgxy/xss/ /usr/nmgxy/getshell/ /usr/nmgxy/dir/
else
mkdir -p /usr/nmgxy/ /usr/nmgxy/LFI/ /usr/nmgxy/exp/ /usr/nmgxy/sql/ /usr/nmgxy/scan/ /usr/nmgxy/xss/ /usr/nmgxy/getshell/ /usr/nmgxy/dir/
fi
echo "分析结果日志保存在/usr/nmgxy/目录下"
echo ---------------------日志目标文件---------------------------
if ls -l /usr/ | egrep "access";then
echo --------------------统计出现次数最多的前20个IP地址-----------------
cat /usr/access*.* |awk '{print $1}' |sort |uniq -c |sort -rn |head -20 >/usr/nmgxy/top20.log
echo "统计完成"
echo ------------------------SQL注入攻击sql.log----------------
echo "开始分析存在SQL注入的攻击行为，并将结果保存在/usr/nmgxy/sql/目录下"
more /usr/access*.* |egrep "%20select%20|%20and%201=1|%20and%201=2|%20exec|%27exec| information_schema.tables|%20information_schema.tables|%20where%20|%20union%20|%20SELECT%20|%2ctable_name%20|cmdshell|%20table_schema" >/usr/nmgxy/sql/sql.log
echo "分析结束"
awk '{print "共检测到SQL注入攻击" NR"次"}' /usr/nmgxy/sql/sql.log|tail -n1
echo "开始统计SQL注入攻击事件中，出现频率最多的前20个IP地址"
cat /usr/nmgxy/sql/sql.log |awk -F "[" '{print $1}' |sort |uniq -c |sort -rn |head -20 >/usr/nmgxy/sql/top20.log
echo ----------------------------------------------------------
more /usr/nmgxy/sql/top20.log
echo "统计结束"
echo -------------------------扫描器scan.log-------------------
echo "开始分析存在扫描的攻击行为，并将结果保存在/usr/nmgxy/scan/目录下"
more /usr/access*.* |egrep "sqlmap|acunetix|Netsparker|nmap|HEAD" >/usr/nmgxy/scan/scan.log
echo "分析结束"
awk '{print "共检测到扫描攻击" NR"次"}' /usr/nmgxy/scan/scan.log|tail -n1
echo "开始统计扫描攻击事件中，出现频率最多的前20个IP地址"
cat /usr/nmgxy/scan/scan.log |awk -F "[" '{print $1}' |sort |uniq -c |sort -rn |head -20 >/usr/nmgxy/scan/top20.log
echo ---------------------------------------------------------------
more /usr/nmgxy/scan/top20.log
echo "统计结束"
echo -------------------------敏感文件扫描dir.log-------------------
echo "开始分析存在扫描的攻击行为，并将结果保存在/usr/nmgxy/dir/目录下"
more /usr/access*.* |egrep "\.zip|\.rar|\.mdb|\.inc|\.sql|\.config|\.bak|/login.inc.php|/.svn/|/mysql/|config.inc.php|\.bak|wwwroot|网站备份|/gf_admin/|/DataBackup/|/Web.config|/web.config|/1.txt|/test.txt" >/usr/nmgxy/dir/dir.log
echo "分析结束"
echo "二次分析结果中HTTP响应码为200和500，结果另存为/usr/nmgxy/dir/ok.log"
more /usr/nmgxy/dir/dir.log | awk '{if($9=200) {print $1" "$2" "$3" "$4" "$6" "$7" "$8" "$9}}' >/usr/nmgxy/dir/ok.log
more /usr/nmgxy/dir/dir.log | awk '{if($9=500) {print $1" "$2" "$3" "$4" "$6" "$7" "$8" "$9}}' >>/usr/nmgxy/dir/ok.log
echo "二次分析结束"
awk '{print "共检测到针对敏感文件扫描" NR"次"}' /usr/nmgxy/dir/dir.log|tail -n1
echo "开始统计敏感文件扫描事件中，出现频率最多的前20个IP地址"
cat /usr/nmgxy/dir/dir.log |awk -F "[" '{print $1}' |sort |uniq -c |sort -rn |head -20 >/usr/nmgxy/dir/top20.log
echo ---------------------------------------------------------------
more /usr/nmgxy/dir/top20.log
echo "统计结束"
echo -------------------------漏洞利用exp.log-------------------
echo "开始分析存在漏洞利用的攻击行为，并将结果保存在/usr/nmgxy/exp/目录下"
more /usr/access*.* |egrep "struts|jmx-console|ajax_membergroup.php|iis.txt|phpMyAdmin|getWriter|dirContext|phpmyadmin|acunetix.txt|/e/|/SouthidcEditor/|/DatePicker/" >/usr/nmgxy/exp/exp.log
echo "分析结束"
awk '{print "共检测到漏洞利用" NR"次"}' /usr/nmgxy/exp/exp.log|tail -n1
echo "开始统计漏洞利用攻击事件中，出现频率最多的前20个IP地址"
cat /usr/nmgxy/exp/exp.log |awk -F "[" '{print $1}' |sort |uniq -c |sort -rn |head -20 >/usr/nmgxy/exp/top20.log
echo ---------------------------------------------------------------
cat /usr/nmgxy/exp/top20.log
echo "统计结束"
echo -------------------------文件包含LFI.log--------------------
echo "开始分析存在利用文件包含漏洞的攻击行为，并将结果保存在/usr/nmgxy/LFI/目录下"
more /usr/access*.* |egrep "/passwd|%00|/win.ini|/my.ini|/MetaBase.xml|/ServUDaemon.ini|cmd.exe" >/usr/nmgxy/LFI/LFI.log
echo "分析结束"
echo "二次分析结果中HTTP响应码为200和500，结果另存为/usr/nmgxy/LFI/ok.log"
more /usr/nmgxy/LFI/LFI.log | awk '{if($9=200) {print $1" "$2" "$3" "$4" "$6" "$7" "$8" "$9}}' >/usr/nmgxy/LFI/ok.log
more /usr/nmgxy/LFI/LFI.log | awk '{if($9=500) {print $1" "$2" "$3" "$4" "$6" "$7" "$8" "$9}}' >>/usr/nmgxy/LFI/ok.log
echo "二次分析结束"
awk '{print "共检测到LFI本地文件包含" NR"次"}' /usr/nmgxy/LFI/LFI.log|tail -n1
echo "开始统计漏洞利用攻击事件中，出现频率最多的前20个IP地址"
cat /usr/nmgxy/LFI/LFI.log |awk -F "[" '{print $1}' |sort |uniq -c |sort -rn |head -20 >/usr/nmgxy/LFI/top20.log
echo ---------------------------------------------------------------
more /usr/nmgxy/LFI/top20.log
echo "统计结束"
echo -------------------------getshell-getshell.log----------------
echo "开始分析存在getshell的攻击行为，并将结果保存在/usr/nmgxy/getshell/目录下"
more /usr/access*.* |egrep " eval|%eval|%execute|%3binsert|%20makewebtaski%20|/div.asp|/1.asp|/1.jsp|/1.php|/1.aspx|xiaoma.jsp|tom.jsp|py.jsp|k8cmd.jsp|/k8cmd|ver007.jsp|ver008.jsp|ver007|ver008|%if|\.aar" >>/usr/nmgxy/getshell/getshell.log
echo "分析结束"
echo "二次分析结果中HTTP响应码为200和500，结果另存为/usr/nmgxy/getshell/ok.log"
more /usr/nmgxy/getshell/getshell.log | awk '{if($9=200) {print $1" "$2" "$3" "$4" "$6" "$7" "$8" "$9}}' >/usr/nmgxy/getshell/ok.log
more /usr/nmgxy/getshell/getshell.log | awk '{if($9=500) {print $1" "$2" "$3" "$4" "$6" "$7" "$8" "$9}}' >>/usr/nmgxy/getshell/ok.log
echo "二次分析结束"
awk '{print "共检测到getshell行为" NR "次"}' /usr/nmgxy/getshell/getshell.log|tail -n1
echo "开始统计漏洞利用攻击事件中，出现频率最多的前20个IP地址"
cat /usr/nmgxy/getshell/getshell.log |awk -F "[" '{print $1}' |sort |uniq -c |sort -rn |head -20 >/usr/nmgxy/getshell/top20.log
echo ---------------------------------------------------------------
more /usr/nmgxy/getshell/top20.log
echo "统计结束"
echo -------------------------xss跨站脚本攻击xss.log--------------------
echo "开始分析存在XSS跨站脚本攻击的攻击行为，并将结果保存在/usr/nmgxy/xss/目录下"
more /usr/access*.* |egrep "<script|javascript| onerror| oneclick| onload|<img|alert|document|cookie" >/usr/nmgxy/xss/xss.log
echo "分析结束"
awk '{print "共检测到XSS跨站脚本攻击" NR"次"}' /usr/nmgxy/xss/xss.log|tail -n1
echo "开始统计XSS跨站脚本攻击事件中，出现频率最多的前20个IP地址"
cat /usr/nmgxy/xss/xss.log |awk -F "[" '{print $1}' |sort |uniq -c |sort -rn |head -20 >/usr/nmgxy/xss/top20.log
echo ---------------------------------------------------------------
more /usr/nmgxy/xss/top20.log
echo "统计结束"
echo "分析已完成，请到/usr/nmgxy/目录下查看结果"
else
echo "IIS日志分析"
echo --------------------统计出现次数最多的前20个IP地址-----------------
cat /usr/ex*.log |awk '{print $10}' |sort |uniq -c |sort -rn |head -20 >/usr/nmgxy/top20.log
echo "统计完成"
echo ------------------------SQL注入攻击sql.log----------------
echo "开始分析存在SQL注入的攻击行为，并将结果保存在/usr/nmgxy/sql/目录下"
more /usr/ex*.log |egrep "%20select%20|%20and%201=1|%20and%201=2|%20where%20|%20union%20|%20SELECT%20|%2ctable_name%20|cmdshell|%20sysobjects|IS_SRVROLEMEMBER|%20is_srvrolemember|%20IS_MEMBER|db_owner|%20HAS_DBACCESS|%20has_dbaccess" >/usr/nmgxy/sql/sql.log
echo "分析结束"
awk '{print "共检测到SQL注入攻击" NR"次"}' /usr/nmgxy/sql/sql.log|tail -n1
echo "开始统计SQL注入攻击事件中，出现频率最多的前20个IP地址"
cat /usr/nmgxy/sql/sql.log |awk '{print $10}' |sort |uniq -c |sort -rn |head -20 >/usr/nmgxy/sql/top20.log
echo ---------------------------------------------------------------
more /usr/nmgxy/sql/top20.log
echo "统计结束"
echo -------------------------扫描器scan.log-------------------
echo "开始分析存在扫描的攻击行为，并将结果保存在/usr/nmgxy/scan/目录下"
more /usr/ex*.log |egrep "sqlmap|acunetix|Netsparker|nmap|HEAD" >/usr/nmgxy/scan/scan.log
echo "分析结束"
awk '{print "共检测到扫描攻击" NR"次"}' /usr/nmgxy/scan/scan.log|tail -n1
echo "开始统计扫描攻击事件中，出现频率最多的前20个IP地址"
cat /usr/nmgxy/scan/scan.log |awk '{print $10}' |sort |uniq -c |sort -rn |head -20 >/usr/nmgxy/scan/top20.log
echo ---------------------------------------------------------------
more /usr/nmgxy/scan/top20.log
echo "统计结束"
echo -------------------------敏感文件扫描dir.log-------------------
echo "开始分析存在扫描的攻击行为，并将结果保存在/usr/nmgxy/dir/目录下"
more /usr/ex*.log |egrep "\.rar|\.zip|\.mdb|\.inc|\.sql|\.config|\.bak|/login.inc.php|/.svn/|/mysql/|/config.inc.php|\.bak|wwwroot|网站备份|/gf_admin/|/DataBackup/|/Web.config|/web.config|/1.txt|/test.txt" >/usr/nmgxy/dir/dir.log
echo "分析结束"
echo "二次分析结果中HTTP响应码为200和500，结果另存为/usr/nmgxy/dir/ok.log"
more /usr/nmgxy/dir/dir.log | egrep " 200" >/usr/nmgxy/dir/ok.log
more /usr/nmgxy/dir/dir.log | egrep " 500" >>/usr/nmgxy/dir/ok.log
echo "二次分析结束"
awk '{print "共检测到针对敏感文件扫描" NR"次"}' /usr/nmgxy/dir/dir.log|tail -n1
echo "开始统计敏感文件扫描事件中，出现频率最多的前20个IP地址"
cat /usr/nmgxy/dir/dir.log |awk '{print $10}' |sort |uniq -c |sort -rn |head -20 >/usr/nmgxy/dir/top20.log
echo ---------------------------------------------------------------
more /usr/nmgxy/dir/top20.log
echo "统计结束"
echo -------------------------漏洞利用exp.log-------------------
echo "开始分析存在漏洞利用的攻击行为，并将结果保存在/usr/nmgxy/exp/目录下"
more /usr/ex*.log |egrep "/jeecms/|/web-console/|struts|/jmx-console/|ajax_membergroup.php|/iis.txt|phpMyAdmin|getWriter|dirContext|phpmyadmin|acunetix.txt|/e/|/SouthidcEditor/|/DatePicker/" >/usr/nmgxy/exp/exp.log
echo "分析结束"
awk '{print "共检测到漏洞利用" NR"次"}' /usr/nmgxy/exp/exp.log|tail -n1
echo "开始统计漏洞利用攻击事件中，出现频率最多的前20个IP地址"
cat /usr/nmgxy/exp/exp.log |awk '{print $10}' |sort |uniq -c |sort -rn |head -20 >/usr/nmgxy/exp/top20.log
echo ---------------------------------------------------------------
more /usr/nmgxy/exp/top20.log
echo "统计结束"
echo -------------------------文件包含LFI.log--------------------
echo "开始分析存在利用文件包含漏洞的攻击行为，并将结果保存在/usr/nmgxy/LFI/目录下"
more /usr/ex*.log |egrep "/passwd|%00|/win.ini|/my.ini|/MetaBase.xml|/ServUDaemon.ini" >/usr/nmgxy/LFI/LFI.log
echo "分析结束"
echo "二次分析结果中HTTP响应码为200和500，结果另存为/usr/nmgxy/LFI/ok.log"
more /usr/nmgxy/LFI/LFI.log | egrep " 200" >/usr/nmgxy/LFI/ok.log
more /usr/nmgxy/LFI/LFI.log | egrep " 500" >>/usr/nmgxy/LFI/ok.log
awk '{print "共检测到LFI本地文件包含" NR"次"}' /usr/nmgxy/LFI/LFI.log|tail -n1
echo "二次分析结束"
echo "开始统计漏洞利用攻击事件中，出现频率最多的前20个IP地址"
cat /usr/nmgxy/LFI/LFI.log |awk '{print $10}' |sort |uniq -c |sort -rn |head -20 >/usr/nmgxy/LFI/top20.log
echo ---------------------------------------------------------------
more /usr/nmgxy/LFI/top20.log
echo "统计结束"
echo -------------------------getshell-getshell.log----------------
echo "开始分析存在getshell的攻击行为，并将结果保存在/usr/nmgxy/getshell/目录下"
more /usr/ex*.log |egrep "%20exec|%27exec|%3bexec|%27%3Bexec|%eval|%20eval|%execute|%3Binsert|%20makewebtaski|%20disk%20|%3Balter|%3Bdeclare|dbo|hack523|sysname|/1.asp|/1.jsp|/1.php|/1.aspx|xiaoma.asp|yijuhua.asp|yjh.asp|hack.asp|k8cmd.jsp|/k8cmd|ver007.jsp|ver008.jsp|ver007|ver008|\.asa|\.cer|\.ashx|asp;|asa;" >>/usr/nmgxy/getshell/getshell.log
echo "分析结束"
echo "二次分析结果中HTTP响应码为200和500，结果另存为/usr/nmgxy/getshell/ok.log"
more /usr/nmgxy/getshell/getshell.log | egrep " 200" >/usr/nmgxy/getshell/ok.log
more /usr/nmgxy/getshell/getshell.log | egrep " 500" >>/usr/nmgxy/getshell/ok.log
echo "二次分析结束"
awk '{print "共检测到getshell行为" NR "次"}' /usr/nmgxy/getshell/getshell.log|tail -n1
echo "开始统计漏洞利用攻击事件中，出现频率最多的前20个IP地址"
cat /usr/nmgxy/getshell/getshell.log |awk '{print $10}' |sort |uniq -c |sort -rn |head -20 >/usr/nmgxy/getshell/top20.log
echo ---------------------------------------------------------------
more /usr/nmgxy/getshell/top20.log
echo "统计结束"
echo -------------------------xss跨站脚本攻击xss.log--------------------
echo "开始分析存在XSS跨站脚本攻击的攻击行为，并将结果保存在/usr/nmgxy/xss/目录下"
more /usr/ex*.log |egrep "<script|javascript|%20onerror|%20oneclick|%20onload|<img|alert|document|cookie" >/usr/nmgxy/xss/xss.log
echo "分析结束"
awk '{print "共检测到XSS跨站脚本攻击" NR"次"}' /usr/nmgxy/xss/xss.log|tail -n1
echo "开始统计XSS跨站脚本攻击事件中，出现频率最多的前20个IP地址"
cat /usr/nmgxy/xss/xss.log |awk '{print $10}' |sort |uniq -c |sort -rn |head -20 >/usr/nmgxy/xss/top20.log
echo ---------------------------------------------------------------
more /usr/nmgxy/xss/top20.log
echo "统计结束"
echo "分析已完成，请到/usr/nmgxy/目录下查看结果"
fi
echo "by 鬼魅羊羔"