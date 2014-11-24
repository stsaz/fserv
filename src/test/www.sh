# usage: ./www.sh dest

FSERV=../..
DEST=$1

mkdir $DEST
cp $FSERV/src/http/status.html $DEST
cp $FSERV/src/http/index.html $DEST
cp $FSERV/src/http/http.c $DEST/gzip.txt

cd $DEST
mkdir dir
touch file0
touch file.htm
echo '123456' > file.txt
