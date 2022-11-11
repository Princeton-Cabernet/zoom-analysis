
export P4_PROGPATH=`pwd`
export P4_PROGNAME=${PWD##*/} 

if [ -z "$SDE" ]
then 
	echo "SDE var not set, assuming located in ~/bf-sde-9.5.0 ..."
	export SDE=$HOME/bf-sde-9.5.0
fi 

export SDE_INSTALL=$SDE/install
export PATH=$SDE_INSTALL/bin:$PATH
export LD_LIBRARY_PATH=/usr/local/lib:$SDE_INSTALL/lib:$LD_LIBRARY_PATH
