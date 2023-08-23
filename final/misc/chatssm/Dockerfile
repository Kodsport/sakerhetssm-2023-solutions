FROM ubuntu:20.04

RUN apt-get update
RUN apt-get install -y python3 python3-pip

RUN pip3 install discord.py

RUN groupadd -g 1337 ctf && useradd -r -u 1337 -g ctf ctf
RUN mkdir -p /home/ctf/

COPY bot.py secrets.py /home/ctf/

RUN chown -R root:ctf /home/ctf/
RUN chmod -R 750 /home/ctf/

CMD python3 /home/ctf/bot.py
