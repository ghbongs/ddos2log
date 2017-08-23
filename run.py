#!/usr/bin/python
# -*-coding:utf8;-*-
import ConfigParser
import glob
import os
import time
import urllib2
from datetime import datetime, timedelta
from xml.etree.ElementTree import Element, tostring, fromstring, ElementTree

from suds.transport.https import HttpAuthenticated
from suds.client import Client
# 파이썬 버그로 ssl접근을 위해 아래 처리
import ssl
ssl._create_default_https_context = ssl._create_unverified_context

# load config
configFileName = "confrun.cfg"
section = "Configuration"
section_detail = "Detail_conf"
section_server = "Server_info"
section_list = "List_conf"
section_save = "Save_conf"


# 프로그램 중복 실행 방지를 위해
# 시작과 종료시 상태값 기록
def set_running(state):
    global config
    config.set(section, "isrunning", state)
    with open(configFileName, 'w') as configfile:
        config.write(configfile)


# Alert List조회
# 파라메터 : 필터, 카운트
# 받아온 String을 xml로 파싱하여 ID와 IP를 리스트에 기록
# 상세 정보 호출시 Crontab주기와 별개로 중복 쿼리가 존재할수 있음으로 중복값 제거
def get1stData():
    # type: () -> object
    global summaryfilter
    global summarycount
    global time_start
    list_client = get_service()
    xmlstr = list_client.service.getDosAlertSummariesXML(summaryfilter,summarycount)
    xml = ElementTree(fromstring(xmlstr))

    # saveXml1stData(xml)

    alertlist = list()

    # All summary alert list
    alertlist_all = list()

    # print ("%s" % xml.findall("."))

    # 수집 기준 시간 (epoch time)
    basetime = int(time.time()) - int(time_start)

    for i in xml.findall("alert"):
        alertlist_all.append((int(i.get("id")), str(i.find("resource").find("ip").text), str(i.find("duration").attrib["stop"]), str(i.find("duration").attrib["start"])))
        if len(i.find("duration").attrib["stop"]) > 0:
            alertlist.append((int(i.get("id")), str(i.find("resource").find("ip").text), str(i.find("duration").attrib["stop"]), str(i.find("duration").attrib["start"])))
            if int(''.join(i.find("duration").attrib["stop"])) >= int(basetime):
                alertlist.append((int(i.get("id")), str(i.find("resource").find("ip").text), str(i.find("duration").attrib["stop"]), str(i.find("duration").attrib["start"])))

    # print ("%s" % alertlist)

    # Alert List를 확인하기 위해 수동으로 확인하기 위해 위함
    # alertlist = list()
    # alertlist.append((int("1254518"), "check", "0","0"))
    ####################################################

    alertlist = list(set(alertlist))
    if alertlist != None:
        logger.info("%s Alertlist : %s", datetime.today().strftime("%Y-%m-%d %H:%M:%S"), alertlist)
        logger.info("%s All Summary Alertlist : %s", datetime.today().strftime("%Y-%m-%d %H:%M:%S"), alertlist_all)
    else:
        logger.info("%s Alertlist is None", datetime.today().strftime("%Y-%m-%d %H:%M:%S"))
    return alertlist


def saveXml1stData(xml):
    global savepath
    global saveprefix
    filename = savepath + "/" + datetime.today().strftime("%Y%m%d%H") + saveprefix + "_1st.txt"
    f = open(filename, "a+")
    f.write(xml)
    # for i in xml.find("query-reply").findall("collector"):
    #     for j in i.findall("flow"):
    #         temp = str(tostring(j, method="xml"))
    #         temp = temp.strip()[1:-3].strip() + "\n"
    #         f.write(temp)



    f.close()



# 상세정보 조회후 xml을 파라메터로 전달받아
# 필요 엘리먼트를 추출한후 lt와 gt문자열 제거후
# 파일에 저장 or 추가
# 파일명 규칙 : 현재시간(년월일시 + Prefix + .txt
def saveXmlData(xml):
    global savepath
    global saveprefix
    filename = savepath + "/" + datetime.today().strftime("%Y%m%d%H") + saveprefix + ".txt"
    f = open(filename, "a+")
    for i in xml.find("query-reply").findall("collector"):
        for j in i.findall("flow"):
            temp = str(tostring(j, method="xml"))
            temp = temp.strip()[1:-3].strip() + "\n"
            f.write(temp)



    f.close()


def saveXmlAlertDetailData(xml, alert_id, dst, stop_time, start_time):
    global savepath
    global saveprefix
    filename = savepath + "/" + datetime.today().strftime("%Y%m%d%H") + saveprefix + ".txt"
    f = open(filename, "a+")

    logger.info("%s Alert_id : %s", datetime.today().strftime("%Y-%m-%d %H:%M:%S"), alert_id)

    isWrite = False
    for i in xml.findall('.//dataset'):
        if (i.attrib["name"] == "src_addr_bytes"):
            cnt = 0
            if isWrite:
                break
            else:
                for j in i.findall("item"):
                    temp = ("stop_time=" + str(stop_time), "start_time=" + str(start_time), "alert_id=" + str(alert_id), "src=" + str(j.attrib["id"]), "dst=" + str(dst), "current=" + str(j.find("class").find("current").attrib["value"]), "avg=" + str(j.find("class").find("avg").attrib["value"]), "max=" + str(j.find("class").find("max").attrib["value"]), "pct95=" + str(j.find("class").find("pct95").attrib["value"]))
                    f.write((str(temp)).replace("'","").strip()[1:-1].strip() + "\n")
                    cnt += 1
                if cnt > 0:
                    logger.info("%s Alert_id : %s Success extract dataset, AlertCount = %d", datetime.today().strftime("%Y-%m-%d %H:%M:%S"), alert_id, cnt)
                    isWrite = True

    f.close()


# 상세 데이터 조회 및 파일 저장
def get2stData(client, id, ip, stop, start):
    alert_id = id
    dst = ip
    stop_time = stop
    start_time = start
    # xmlstr = getXmlForDetail(id, ip)
    # resultstr = client.service.runXmlQuery(xmlstr, "xml")
    # resultstr = client.service.getDosAlertDetailsXML(id, "xml")
    resultstr = client.service.getDosAlertDetailsXML(alert_id, "xml")
    xml = ElementTree(fromstring(resultstr))
    saveXmlAlertDetailData(xml, alert_id, dst, stop_time, start_time)


# Soap 서비스 할당
def get_service():
    global url
    global username
    global password

    wsdl_url = 'file://%s/PeakflowSP.wsdl' % os.getcwd()

    t = HttpAuthenticated(username=username, password=password)
    t.handler = urllib2.HTTPDigestAuthHandler(t.pm)
    t.urlopener = urllib2.build_opener(t.handler)

    client = Client(url=wsdl_url, location=url, transport=t)
    return client


# 상세 정보 조회를 위한 쿼리 생성부
def getXmlForDetail(id, ip):
    global query_type
    global time_start
    global processing_type
    global search_limit
    global search_timeout
    global filter_type

    peakflow = Element("peakflow", version="1.0")

    queryid = Element("query", id=str(id), type=query_type)
    time = Element("time", start_ascii=time_start, end_ascii="now")
    processing = Element("processing", type=processing_type)
    search = Element("search", limit=search_limit, timeout=search_timeout)

    Filter = Element("filter", type=filter_type)
    instance = Element("instance", value="dst " + ip)
    Filter.append(instance)

    queryid.append(time)
    queryid.append(processing)
    queryid.append(search)
    queryid.append(Filter)

    peakflow.append(queryid)
    return tostring(peakflow, encoding="utf8", method="xml")


# 실행 종료 전 지정된 날짜 이전의 데이터는 삭제한다
def clearData():
    global savepath
    global saveprefix
    global deleteintervalday

    timegap = timedelta(days=deleteintervalday)
    before = datetime.now() - timegap
    limitdate = before.strftime("%Y%m%d")

    list = glob.glob(savepath + "*" + saveprefix + ".txt")
    list.sort()
    for i in list:
        date = i.replace(savepath, "").replace(saveprefix, "").replace(".txt", "")
        if date < limitdate:
            os.remove(i)
        else:
            break


# run.py
try:
    #  1. 설정 로드
    config = ConfigParser.RawConfigParser()
    config.read(configFileName)
    # 변수 할당
    isRunning = config.getboolean(section, 'isrunning')

    url = config.get(section_server, "url")
    username = config.get(section_server, "username")
    password = config.get(section_server, "password")

    summaryfilter = config.get(section_list, "summaryfilter")
    summarycount = config.getint(section_list, "summarycount")

    savepath = config.get(section_save, "savepath")
    saveprefix = config.get(section_save, "saveprefix")
    deleteintervalday = config.getint(section_save, "deleteintervalday")

    query_type = config.get(section_detail, "query_type")
    time_start = config.get(section_detail, "time_start")
    processing_type = config.get(section_detail, "processing_type")
    search_limit = config.get(section_detail, "search_limit")
    search_timeout = config.get(section_detail, "search_timeout")
    filter_type = config.get(section_detail, "filter_type")

    import logging
    from logging import handlers

    logger = logging.getLogger("mylogger")
    logger.setLevel(logging.INFO)
    file_handler = handlers.RotatingFileHandler(
        savepath + "/" + saveprefix[1:] + ".log",
        maxBytes=(1024 * 1024 * 5),
        backupCount=5
    )
    logger.addHandler(file_handler)


    if not isRunning:
        logger.info("%s ####################  StartTime  ####################", datetime.today().strftime("%Y-%m-%d %H:%M:%S"))
        set_running(True)
        tempArray = get1stData()
        client = get_service()
        for item in tempArray:
            get2stData(client, int(item[0]), item[1], int(item[2]), int(item[3]))

        set_running(False)
except:
    logger.info("%s ####################  ExceptionTime  ####################", datetime.today().strftime("%Y-%m-%d %H:%M:%S"))
    # print("Exception Time%s" % datetime.today().strftime("%Y-%m-%d %H:%M:%S"))
    set_running(False)

clearData()
logger.info("%s ####################  EndTime  ####################", datetime.today().strftime("%Y-%m-%d %H:%M:%S"))
# print("End       Time : %s" % datetime.today().strftime("%Y-%m-%d %H:%M:%S"))
