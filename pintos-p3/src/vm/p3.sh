#!/bin/bash

# This grading script is intended to show students what would happen when TA
# grade p3 project.
#
# Do the following steps to run the script:
# - copy this script to src/vm/
#
# - change file attribute to allow script execution
#
#   chmod 700 p3.sh
#
# - run this script to start grading
#
#   ./p3.sh
#
# This script will download pintos-raw and extract it to ~/cs230-grading/pintos,
# copy specific files that you are allowed to modify there, and do the grading
# on ~/cs230-grading/pintos.

cd ../

rm -rf ~/cs230-grading &> /dev/null

# Download the pintos-raw code and extract it.
wget https://www.classes.cs.uchicago.edu/current/23000-1/proj/files/pintos-raw.tgz -P ~/cs230-grading
tar -zxvf ~/cs230-grading/pintos-raw.tgz -C ~/cs230-grading/
rm ~/cs230-grading/pintos-raw.tgz
mv ~/cs230-grading/pintos-raw ~/cs230-grading/pintos

# Determine the acceptable changed files and copy it from the student directory
# to the temporary grading directory. Notice that in here we have several files since p3 requires both finished p2
# and modified files from p1/p2.
files=(Makefile.build
       threads/init.c
       threads/interrupt.c
       threads/thread.c
       threads/thread.h
       userprog/exception.c
       userprog/process.c
       userprog/syscall.c
       userprog/syscall.h
       userprog/pagedir.c
       devices/timer.c
       vm/frame.c
       vm/frame.h
       vm/page.c
       vm/page.h
       vm/swap.c
       vm/swap.h)

for file in ${files[@]}; do
    echo "Copying [$file]"
    cp $file ~/cs230-grading/pintos/src/$file
done

cd ~/cs230-grading/pintos/src/vm/

make 2> /dev/null

cd build/

make check > check_output

##########################################################################################
# Grading functions
##########################################################################################

calc() {
    echo "scale=4; $1" | bc ;exit
}

function cal(){
    if [ "$1" -eq "1" ] ; then
  sumrf=$((sumrf+3));
    fi
    if [ "$1" -eq "2" ] ; then
  sumrf=$((sumrf+3));
    fi
    if [ "$1" -eq "3" ] ; then
  sumrf=$((sumrf+3));
    fi
    if [ "$1" -eq "4" ] ; then
  sumrf=$((sumrf+3));
    fi
    if [ "$1" -eq "5" ] ; then
  sumrf=$((sumrf+3));
    fi
    if [ "$1" -eq "13" ] ; then
  sumrf=$((sumrf+3));
    fi
    if [ "$1" -eq "16" ] ; then
  sumrf=$((sumrf+3));
    fi
    if [ "$1" -eq "12" ] ; then
  sumrf=$((sumrf+3));
    fi
    if [ "$1" -eq "17" ] ; then
  sumrf=$((sumrf+3));
    fi
    if [ "$1" -eq "20" ] ; then
  sumrf=$((sumrf+3));
    fi
    if [ "$1" -eq "19" ] ; then
  sumrf=$((sumrf+3));
    fi
    if [ "$1" -eq "25" ] ; then
  sumrf=$((sumrf+3));
    fi
    if [ "$1" -eq "31" ] ; then
  sumrf=$((sumrf+3));
    fi
    if [ "$1" -eq "34" ] ; then
  sumrf=$((sumrf+3));
    fi
    if [ "$1" -eq "37" ] ; then
  sumrf=$((sumrf+3));
    fi
    if [ "$1" -eq "40" ] ; then
  sumrf=$((sumrf+3));
    fi
    if [ "$1" -eq "26" ] ; then
  sumrf=$((sumrf+3));
    fi
    if [ "$1" -eq "43" ] ; then
  sumrf=$((sumrf+5));
    fi
    if [ "$1" -eq "45" ] ; then
  sumrf=$((sumrf+5));
    fi
    if [ "$1" -eq "44" ] ; then
  sumrf=$((sumrf+5));
    fi
    if [ "$1" -eq "48" ] ; then
  sumrf=$((sumrf+5));
    fi
    if [ "$1" -eq "49" ] ; then
  sumrf=$((sumrf+5));
    fi
    if [ "$1" -eq "11" ] ; then
  sumrf=$((sumrf+5));
    fi
    if [ "$1" -eq "10" ] ; then
  sumrf=$((sumrf+3));
    fi
    if [ "$1" -eq "52" ] ; then
  sumrf=$((sumrf+15));
    fi
    if [ "$1" -eq "54" ] ; then
  sumrf=$((sumrf+3));
    fi
    if [ "$1" -eq "55" ] ; then
  sumrf=$((sumrf+3));
    fi
    if [ "$1" -eq "56" ] ; then
  sumrf=$((sumrf+3));
    fi
    if [ "$1" -eq "28" ] ; then
  sumrb=$((sumrb+2));
    fi
    if [ "$1" -eq "29" ] ; then
  sumrb=$((sumrb+2));
    fi
    if [ "$1" -eq "30" ] ; then
  sumrb=$((sumrb+2));
    fi
    if [ "$1" -eq "27" ] ; then
  sumrb=$((sumrb+2));
    fi
    if [ "$1" -eq "36" ] ; then
  sumrb=$((sumrb+2));
    fi
    if [ "$1" -eq "35" ] ; then
  sumrb=$((sumrb+2));
    fi
    if [ "$1" -eq "42" ] ; then
  sumrb=$((sumrb+2));
    fi
    if [ "$1" -eq "41" ] ; then
  sumrb=$((sumrb+2));
    fi
    if [ "$1" -eq "53" ] ; then
  sumrb=$((sumrb+2));
    fi
    if [ "$1" -eq "15" ] ; then
  sumrb=$((sumrb+3));
    fi
    if [ "$1" -eq "47" ] ; then
  sumrb=$((sumrb+3));
    fi
    if [ "$1" -eq "24" ] ; then
  sumrb=$((sumrb+3));
    fi
    if [ "$1" -eq "32" ] ; then
  sumrb=$((sumrb+3));
    fi
    if [ "$1" -eq "38" ] ; then
  sumrb=$((sumrb+3));
    fi
    if [ "$1" -eq "18" ] ; then
  sumrb=$((sumrb+3));
    fi
    if [ "$1" -eq "21" ] ; then
  sumrb=$((sumrb+3));
    fi
    if [ "$1" -eq "33" ] ; then
  sumrb=$((sumrb+3));
    fi
    if [ "$1" -eq "39" ] ; then
  sumrb=$((sumrb+3));
    fi
    if [ "$1" -eq "14" ] ; then
  sumrb=$((sumrb+2));
    fi
    if [ "$1" -eq "23" ] ; then
  sumrb=$((sumrb+2));
    fi
    if [ "$1" -eq "22" ] ; then
  sumrb=$((sumrb+2));
    fi
    if [ "$1" -eq "7" ] ; then
  sumrb=$((sumrb+3));
    fi
    if [ "$1" -eq "6" ] ; then
  sumrb=$((sumrb+3));
    fi
    if [ "$1" -eq "8" ] ; then
  sumrb=$((sumrb+5));
    fi
    if [ "$1" -eq "9" ] ; then
  sumrb=$((sumrb+5));
    fi
    if [ "$1" -eq "46" ] ; then
  sumrb=$((sumrb+5));
    fi
    if [ "$1" -eq "51" ] ; then
  sumrb=$((sumrb+5));
    fi
    if [ "$1" -eq "50" ] ; then
  sumrb=$((sumrb+5));
    fi
    if [ "$1" -eq "57" ] ; then
  sumrb=$((sumrb+1));
    fi
    if [ "$1" -eq "58" ] ; then
  sumrb=$((sumrb+1));
    fi
    if [ "$1" -eq "61" ] ; then
  sumrb=$((sumrb+1));
    fi
    if [ "$1" -eq "59" ] ; then
  sumrb=$((sumrb+1));
    fi
    if [ "$1" -eq "60" ] ; then
  sumrb=$((sumrb+1));
    fi
    if [ "$1" -eq "62" ] ; then
  sumrb=$((sumrb+1));
    fi
    if [ "$1" -eq "63" ] ; then
  sumvrf=$((sumvrf+3));
    fi
    if [ "$1" -eq "71" ] ; then
  sumvrf=$((sumvrf+3));
    fi
    if [ "$1" -eq "66" ] ; then
  sumvrf=$((sumvrf+3));
    fi
    if [ "$1" -eq "64" ] ; then
  sumvrf=$((sumvrf+3));
    fi
    if [ "$1" -eq "72" ] ; then
  sumvrf=$((sumvrf+3));
    fi
    if [ "$1" -eq "73" ] ; then
  sumvrf=$((sumvrf+3));
    fi
    if [ "$1" -eq "78" ] ; then
  sumvrf=$((sumvrf+3));
    fi
    if [ "$1" -eq "74" ] ; then
  sumvrf=$((sumvrf+4));
    fi
    if [ "$1" -eq "75" ] ; then
  sumvrf=$((sumvrf+4));
    fi
    if [ "$1" -eq "77" ] ; then
  sumvrf=$((sumvrf+4));
    fi
    if [ "$1" -eq "76" ] ; then
  sumvrf=$((sumvrf+4));
    fi
    if [ "$1" -eq "79" ] ; then
  sumvrf=$((sumvrf+2));
    fi
    if [ "$1" -eq "84" ] ; then
  sumvrf=$((sumvrf+2));
    fi
    if [ "$1" -eq "86" ] ; then
  sumvrf=$((sumvrf+2));
    fi
    if [ "$1" -eq "83" ] ; then
  sumvrf=$((sumvrf+2));
    fi
    if [ "$1" -eq "81" ] ; then
  sumvrf=$((sumvrf+2));
    fi
    if [ "$1" -eq "85" ] ; then
  sumvrf=$((sumvrf+1));
    fi
    if [ "$1" -eq "88" ] ; then
  sumvrf=$((sumvrf+3));
    fi
    if [ "$1" -eq "80" ] ; then
  sumvrf=$((sumvrf+2));
    fi
    if [ "$1" -eq "95" ] ; then
  sumvrf=$((sumvrf+2));
    fi
    if [ "$1" -eq "67" ] ; then
  sumvrb=$((sumvrb+2));
    fi
    if [ "$1" -eq "68" ] ; then
  sumvrb=$((sumvrb+3));
    fi
    if [ "$1" -eq "69" ] ; then
  sumvrb=$((sumvrb+2));
    fi
    if [ "$1" -eq "70" ] ; then
  sumvrb=$((sumvrb+3));
    fi
    if [ "$1" -eq "65" ] ; then
  sumvrb=$((sumvrb+4));
    fi
    if [ "$1" -eq "87" ] ; then
  sumvrb=$((sumvrb+1));
    fi
    if [ "$1" -eq "89" ] ; then
  sumvrb=$((sumvrb+1));
    fi
    if [ "$1" -eq "91" ] ; then
  sumvrb=$((sumvrb+1));
    fi
    if [ "$1" -eq "96" ] ; then
  sumvrb=$((sumvrb+1));
    fi
    if [ "$1" -eq "90" ] ; then
  sumvrb=$((sumvrb+2));
    fi
    if [ "$1" -eq "92" ] ; then
  sumvrb=$((sumvrb+2));
    fi
    if [ "$1" -eq "93" ] ; then
  sumvrb=$((sumvrb+2));
    fi
    if [ "$1" -eq "94" ] ; then
  sumvrb=$((sumvrb+2));
    fi
    if [ "$1" -eq "82" ] ; then
  sumvrb=$((sumvrb+2));
    fi


    if [ "$1" -ge "97" ] && [ "$1" -le "109" ] ; then
  sumfile=$((sumfile+5));
    fi
}

sumrf=0;
sunrb=0;
sumvrf=0;
sumvrb=0;
sumfile=0;
sumtotal=0;
sum=0;
while read line
do
    pass=$(echo $line | grep "pass");
    i=$(($i+1));
    if [ ! -z "$pass" ]; then
  cal $i
    fi
done < results

echo ""
echo "sum of /userprog/Rubric.functionality is :$sumrf (108) emphasis: 10%"
echo "sum of /userprog/Rubric.robustness is :$sumrb (88) emphasis: 5%"
echo "sum of /vm/Rubric.functionality is :$sumvrf (55) emphasis: 50%"
echo "sum of /vm/Rubric.robustness is :$sumvrb (28) emphasis: 15%"
echo "sum of /filesys/base/Rubric is :$sumfile (65) emphasis: 20%"
sumtotal=$(calc $(calc $(calc $sumrf*10)/108)+$(calc $(calc $sumrb*5)/88)+$(calc $(calc $sumvrf*50)/55)+$(calc $(calc $sumvrb*15)/28)+$(calc $(calc $sumfile*20)/65))
sum=$(calc $(calc $sumtotal*90)/100)

if [ "$sum" = "" ]; then
   sum=0
fi 

echo "Total grade out of 90: $sum"
echo ""

##########################################################################################
##########################################################################################

# Delete the temporary grading directory.
rm -rf ~/cs230-grading &> /dev/null
