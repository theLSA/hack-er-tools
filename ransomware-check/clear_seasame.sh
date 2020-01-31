#!/usr/bin/env bash

function log() { echo "$1";echo "$1" >> ./log.txt; }

log "Begin time:"
log "`date`"

malicious_hash_arr=("cd4bf850a354a80eb860586d253a4385" "d71eb083e7943f0641982797c09f3e73" "3e86ec46f977a954f304d64ffeadf062")
is_infected=0

#get new_bash filename and clear malicious files
bashmd5=$(md5sum `command -v bash` | cut -d ' ' -f1)
new_bash=""
findfiles=$(find /tmp -xdev -type f)
for file in ${findfiles[@]};do
	filemd5=$(md5sum "$file" | cut -d ' ' -f1)
	for malhash in ${malicious_hash_arr[@]};do
		if [ $filemd5 = $malhash ];then
			log "Delete malicious file $file:$filemd5"
			rm $file
			is_infected=1
		fi
	done
	if [ $filemd5 = $bashmd5 ];then
		log "new_bash path is : $file"
		new_bash=`basename $file`
		log "new_bash name is : $new_bash"
	fi
done

if [ $is_infected == 0 ];then
	log "Not infected."
	exit
else
	log "Infected."
fi

#kill malicious processes
if [ -n $new_bash ];then
	findpids=$(ps -el | grep $new_bash | grep -v grep | awk '{print $4}')
	for pid in ${findpids[@]};do
		log "Kill maliciours process $pid :"
		log "`ps -up $pid`"
		kill -9 $pid
	done
fi

#kill miner processe
findpids=$(ps aux | grep '/boot/vmlinuz' | awk '{if($3>30.0) print $2}')
for pid in ${findpids[@]};do
	log "Kill miner process $pid :"
	log "`ps -up $pid`"
	kill -9 $pid
done

#delete malicious crontab
log "crontab is :"
log "--------------------------------------------------------------"
log "`crontab -l`"
log "--------------------------------------------------------------"
log "Delete malicious crontab."
crontab -l | grep -v '/tmp/seasame' | crontab -

#delete malicious service
malicious_service="/etc/systemd/system/cloud_agent.service"
if [ -f $malicious_service ]; then
	log "cloud_agent.service is :"
	log "--------------------------------------------------------------"
	log "`cat $malicious_service`"
	log "--------------------------------------------------------------"
	grep "/tmp/seasame" $malicious_service > /dev/null
	if [ $? -eq 0 ]; then
		log "Delete malicious service."
		rm $malicious_service
	else
		log "Not found malicious service."
	fi
fi
log "End time:"
log "`date`"