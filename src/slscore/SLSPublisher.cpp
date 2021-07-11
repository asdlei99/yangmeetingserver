
/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2019-2020 Edward.Wu
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */


#include <errno.h>
#include <string.h>
#include "yangsrt/include/YangTsPid.h"

#include "SLSPublisher.hpp"
#include "SLSPlayer.hpp"
#include "SLSLog.hpp"

/**
 * app conf
 */
SLS_CONF_DYNAMIC_IMPLEMENT(app)

/**
 * CSLSPublisher class implementation
 */

CSLSPublisher::CSLSPublisher()
{

	m_meetingId=0;
	m_roleId=10;
    m_is_write             = 0;
    m_map_publisher        = NULL;
#if  Yang_Using_SrtDataServer
    m_userId=0;
    m_meetingMap = NULL;
#endif
    sprintf(m_role_name, "publisher");


}

CSLSPublisher::~CSLSPublisher()
{
    //release
#if  Yang_Using_SrtDataServer
	m_meetingMap = NULL;
#endif
}

void CSLSPublisher::set_map_meeting(YangMapMeeting *pmeeting){
#if  Yang_Using_SrtDataServer
	m_meetingMap=pmeeting;
#endif
}


void CSLSPublisher::setUserId(int puserId){
#if  Yang_Using_SrtDataServer
	m_userId=puserId;
#endif
}

void CSLSPublisher::setMeetingId(int pmeetingId){
	m_meetingId=pmeetingId;
}

int CSLSPublisher::init()
{
    int ret = CSLSRole::init();
    if (m_conf) {
        sls_conf_app_t * app_conf = ((sls_conf_app_t *)m_conf);
        //m_exit_delay = ((sls_conf_app_t *)m_conf)->publisher_exit_delay;
        strcpy(m_record_hls, app_conf->record_hls);
        m_record_hls_segment_duration = app_conf->record_hls_segment_duration;
    }

    return ret;
}

int CSLSPublisher::uninit()
{
    int ret = SLS_OK;

	if (m_map_data) {
        ret = m_map_data->remove(m_map_data_key);
		sls_log(SLS_LOG_INFO, "[%p]CSLSPublisher::uninit, removed publisher from m_map_data, ret=%d.",
				this, ret);
	}

	if (m_map_publisher) {
        ret = m_map_publisher->remove(this);
		sls_log(SLS_LOG_INFO, "[%p]CSLSPublisher::uninit, removed publisher from m_map_publisher, ret=%d.",
				this, ret);
	}
	//printf("\n0....................CSLSPublisher remove....userId==%d\n",m_userId);
#if  Yang_Using_SrtDataServer
	if(m_meetingMap&&m_meetingMap->m_usingSrtDataChannel){
		printf("\n1....................CSLSPublisher remove....userId==%d\n",m_userId);
		m_meetingMap->removeUser(m_meetingId,m_userId);
	}
#endif
    return CSLSRole::uninit();
}

void CSLSPublisher::set_map_publisher(CSLSMapPublisher * publisher)
{
	m_map_publisher = publisher;
}
#if  Yang_Using_SrtDataServer
void CSLSPublisher::sendCommand(char *p,int plen){

	map<std::string, CSLSRole *> *pubmap=m_map_publisher->get_publisher_map();
//	if(!pubmap) return;

	printf("\n...%d*********************sendCommand==%d**\n",(int)pubmap->size(),plen);
	m_meetingMap->commandHandle(m_meetingId,(unsigned char*)p,plen);

	for(map<std::string, CSLSRole *>::iterator iter=pubmap->begin();iter!=pubmap->end();iter++){
		//printf("\n********************************roleId=%d**************meetingId==%d******",iter->second->m_roleId,iter->second->m_roleId);
		//printf("\n***rolId==%d,meetingId==%d",iter->second->m_roleId,iter->second->m_meetingId);
		if(iter->second->m_roleId==10&&iter->second->m_meetingId==m_meetingId){

			iter->second->write(p,plen);
		}
	}
	pubmap=NULL;
}
#endif
int CSLSPublisher::handler()
{
	//((data_p[pos]<<8)|data_p[pos+1])&0x1FFF;
    //return handler_read_data();
	int64_t *last_read_time=NULL;
	char szData[TS_UDP_LEN];
	//printf("\n0********************************CSLSPublisher::handler\n");
		if (SLS_OK != check_http_passed()) {
			return SLS_OK;
		}

		if (NULL == m_srt) {
	        sls_log(SLS_LOG_ERROR, "[%p]CSLSRole::handler_read_data, m_srt is null.", this);
		    return SLS_ERROR;
		}
	    //read data
	    int n = m_srt->libsrt_read(szData, TS_UDP_LEN);
		if (n <= 0) {
	        sls_log(SLS_LOG_ERROR, "[%p]CSLSRole::handler_read_data, libsrt_read failure, n=%d.", this, n, TS_UDP_LEN);
		    return SLS_ERROR;
		}
		//printf("\n1********************************CSLSPublisher::handler\n");
#if  Yang_Using_SrtDataServer
		if(m_meetingMap->m_usingSrtDataChannel){
			int pid=((szData[1] & 0x1F) << 8) | (szData[2]&0xFF);
			if(pid==Yang_PRIVATE_PID){
				sendCommand(szData,n);
				return SLS_OK;
			}
		}
#endif
		m_stat_bitrate_datacount += n;
		//update invalid begin time
		m_invalid_begin_tm = sls_gettime_ms();
		int d = m_invalid_begin_tm - m_stat_bitrate_last_tm;
		if (d >= m_stat_bitrate_interval) {
			m_kbitrate = m_stat_bitrate_datacount*8/d;
			m_stat_bitrate_datacount = 0;
			m_stat_bitrate_last_tm = m_invalid_begin_tm;
		}

		if (n != TS_UDP_LEN) {
	        sls_log(SLS_LOG_TRACE, "[%p]CSLSRole::handler_read_data, libsrt_read n=%d, expect %d.", this, n, TS_UDP_LEN);
	        //return SLS_ERROR;
	    }

	    if (NULL == m_map_data) {
	        sls_log(SLS_LOG_ERROR, "[%p]CSLSRole::handler_read_data, no data handled, m_map_data is NULL.", this);
	        return SLS_ERROR;
	    }

	    sls_log(SLS_LOG_TRACE, "[%p]CSLSRole::handler_read_data, ok, libsrt_read n=%d.", this, n);
	    int ret = m_map_data->put(m_map_data_key, szData, n, last_read_time);

	    //record data
	    if (strcmp(m_record_hls, "on") == 0) {
	        record_data2hls(szData, n);
	    }

	    return ret;
}



