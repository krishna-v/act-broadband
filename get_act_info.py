#!/usr/bin/env python3

'''
get_act_info.py
Author: Krishna V
https://github.com/krishna-v/act-broadband/get_act_info.py

Description: Scrapes the (truly horrendous) Web Portal of ACT Broadband
and extracts account and usage information for the current user.

Usage information is sometimes buggy and may not be retrieved consistently.
Suggestions welcome to improve.
'''

import argparse
from bs4 import BeautifulSoup
from http.cookiejar import CookieJar
from urllib import request, parse
import json

def get_postdata(page_id, context):
    data_ = {
        "_ACTMyAccount_WAR_ACTMyAccountportlet_:j_idt35": "_ACTMyAccount_WAR_ACTMyAccountportlet_:j_idt35",
        "javax.faces.encodedURL": f"https://selfcare.actcorp.in/group/{context.city}/myaccount?p_p_id=ACTMyAccount_WAR_ACTMyAccountportlet&p_p_lifecycle=2&p_p_state=normal&p_p_mode=view&p_p_cacheability=cacheLevelPage&p_p_col_id=column-1&p_p_col_count=3&p_p_col_pos=1&_ACTMyAccount_WAR_ACTMyAccountportlet__jsfBridgeAjax=true&_ACTMyAccount_WAR_ACTMyAccountportlet__facesViewIdResource=%2FWEB-INF%2FPages%2FaccountView%2FaccountView.xhtml",
        "javax.faces.ViewState":   context.viewstate,
        "javax.faces.source":  f"_ACTMyAccount_WAR_ACTMyAccountportlet_:j_idt35:j_idt{page_id}",
        "javax.faces.partial.event":   "click",
        "javax.faces.partial.execute": f"_ACTMyAccount_WAR_ACTMyAccountportlet_:j_idt35:j_idt{page_id} @component",
        "javax.faces.partial.render":  "@component",
        "org.richfaces.ajax.component":    f"_ACTMyAccount_WAR_ACTMyAccountportlet_:j_idt35:j_idt{page_id}",
        f"_ACTMyAccount_WAR_ACTMyAccountportlet_:j_idt35:j_idt{page_id}":  f"_ACTMyAccount_WAR_ACTMyAccountportlet_:j_idt35:j_idt{page_id}",
        "rfExt":   "null",
        "AJAX:EVENTS_COUNT":   "1",
        "javax.faces.partial.ajax":    "true"
    }
    return parse.urlencode(data_).encode('UTF-8')


def write_file(filename, data):
    f = open(filename, "w")
    f.write(data)
    f.close()


def get_acct_info(opener, context):
    accountpage = f"https://selfcare.actcorp.in/group/{context.city}/myaccount"
    page = opener.open(accountpage)
    soup = BeautifulSoup(page.read(), features="lxml")
    if context.debug > 1:
        write_file("acct_info.html", soup.prettify())

    acct_info = {}
    details = soup.find(id="_ACTMyAccount_WAR_ACTMyAccountportlet_:j_idt59_body").find('tbody').find_all('tr')
    for row in details:
        label = row.find('td', {'class' : "mdcol1"}).get_text()
        if label == None or label.strip() == "":
            continue
        label = label.strip().lower()
        data = row.find('td', {'class' : "col2"}).get_text().strip()
        acct_info[label] =  data
    context.viewstate = soup.find(id="javax.faces.ViewState").get('value')
    return acct_info


def get_package_info(opener, context):
    page_id = 39
    page = opener.open(context.portalurl, data=get_postdata(page_id, context))
    soup = BeautifulSoup(page.read(), features="lxml")
    if context.debug > 1:
        write_file("pkg_info.html", soup.prettify())

    pkg_info = {}
    details = soup.find(id="_ACTMyAccount_WAR_ACTMyAccountportlet_:j_idt168:j_idt170_body").find('tbody').find_all('tr')
    for row in details:
        label = row.find('td', {'class' : "packagecol1"}).get_text()
        if label == None or label.strip() == "":
            continue
        label = label.strip().lower()
        data = row.find('td', {'class' : "packagecol3"}).get_text().strip()
        pkg_info[label] =  data
    return pkg_info


def get_usage_info(opener, context):
    page_id = 43
    page = opener.open(context.portalurl, data=get_postdata(page_id, context))
    soup = BeautifulSoup(page.read(), features="lxml")
    if context.debug > 1:
        write_file("usage_info.html", soup.prettify())

    usage_info = {}
    usage_details = []
    usage_total = {}
    usage_tbl = soup.find(id="_ACTMyAccount_WAR_ACTMyAccountportlet_:j_idt310:j_idt328:tb")
    if usage_tbl == None:
        if context.debug:
            print("Failed to fetch usage detail information. Will not populate this section.")
    else:
        details = usage_tbl.find_all('tr')
        for row in details:
            dtl_row = {}
            row_id = row.get('id')
            dtl_row['from'] = row.find(id=f"{row_id}:j_idt329").get_text().strip()
            dtl_row['to'] = row.find(id=f"{row_id}:j_idt331").get_text().strip()
            dtl_row['upload_mb'] = row.find(id=f"{row_id}:j_idt333").get_text().strip()
            dtl_row['download_mb'] = row.find(id=f"{row_id}:j_idt335").get_text().strip()
            dtl_row['total_mb'] = row.find(id=f"{row_id}:j_idt337").get_text().strip()
            usage_details.append(dtl_row)
        usage_info['details'] = usage_details

    total_tbl = soup.find(id="_ACTMyAccount_WAR_ACTMyAccountportlet_:j_idt310:total")
    if total_tbl == None:
        if context.debug:
            print("Failed to fetch usage total information. Will not populate this section.")
    else:
        totals = total_tbl.find_all('td')
        usage_total['total_upload'] = totals[1].get_text().strip()
        usage_total['total_download'] = totals[3].get_text().strip()
        usage_total['total_usage'] = totals[5].get_text().strip()
        usage_info['totals'] = usage_total

    return usage_info
    

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Get some information for current ACT Broadband account.')
    parser.add_argument('-d', '--debug', action='count', default=0, help='debug flag, repeat for more debuggging (e.g. -ddd = debug level 3.)')
    parser.add_argument('-c', '--city', default='blr', help='your ACT broadband city code (default: blr)')
    parser.add_argument('-u', '--usage', action='store_true', help='retrieve detailed usage info')
    parser.add_argument('-o', '--output', default=None, help='output to file instead of stdout')
    context = parser.parse_args()
    context.portalurl = f"https://selfcare.actcorp.in/group/{context.city}/myaccount?p_p_id=ACTMyAccount_WAR_ACTMyAccountportlet&p_p_lifecycle=2&p_p_state=normal&p_p_mode=view&p_p_cacheability=cacheLevelPage&p_p_col_id=column-1&p_p_col_count=3&p_p_col_pos=1&_ACTMyAccount_WAR_ACTMyAccountportlet__jsfBridgeAjax=true&_ACTMyAccount_WAR_ACTMyAccountportlet__facesViewIdResource=%2FWEB-INF%2FPages%2FaccountView%2FaccountView.xhtml"

    if context.debug:
        print("Program Context: ", context)

    act_info = {}
    opener = request.build_opener(request.HTTPCookieProcessor(CookieJar()))
    act_info['account_info'] = get_acct_info(opener, context)
    act_info['package_info'] = get_package_info(opener, context)
    if context.usage:
        act_info['usage_info'] = get_usage_info(opener, context)

    if context.output != None:
       write_file(context.output, json.dumps(act_info, indent=4)) 
    else:
        print(json.dumps(act_info, indent=4))
