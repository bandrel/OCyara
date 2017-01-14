FROM ubuntu:latest
MAINTAINER Justin Bollinger"

RUN apt-get update
RUN apt-get install -y python3 python3-dev tesseract-ocr libtesseract-dev libleptonica-dev python3-pip git virtualenv
RUN pip3 install --upgrade pip
RUN pip3 install yara-python
RUN pip3 install pillow
RUN pip3 install cython
RUN pip3 install tesserocr
RUN pip3 install pytest
WORKDIR /root

