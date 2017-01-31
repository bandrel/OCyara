FROM ubuntu:16.10

RUN apt-get update
RUN apt-get install -y apt-utils
RUN apt-get install -y python3-dev
RUN apt-get install -y tesseract-ocr libtesseract-dev libleptonica-dev libpng-dev libjpeg-dev libtiff5-dev zlib1g-dev
RUN apt-get install -y python3-pip
RUN apt-get install -y python-pip
RUN apt-get install -y python3
RUN apt-get install -y virtualenv
RUN apt-get install -y git
RUN pip3 install --upgrade pip
RUN apt-get install -y wget
RUN pip3 install cython
RUN wget -O requirements.txt https://raw.githubusercontent.com/bandrel/OCyara/master/requirements.txt && pip3 install -r requirements.txt
RUN pip3 install pytest
RUN git clone https://github.com/bandrel/OCyara.git
