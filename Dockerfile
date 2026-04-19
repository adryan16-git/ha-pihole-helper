ARG BUILD_FROM
FROM $BUILD_FROM

RUN pip3 install --no-cache-dir flask

COPY run.sh /run.sh
RUN chmod +x /run.sh

COPY pihole_helper/ /pihole_helper/

CMD ["/run.sh"]
