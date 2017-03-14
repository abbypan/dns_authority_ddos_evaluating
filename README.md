# dns_authority_ddos_evaluating
Evaluating for DDoS attack on Authoritative service  权威拒绝服务攻击影响分析，2013

We evaluated ddos attack of .CN TLD at 2013.8.25. My origin paper was writed at 2014 with Chinese.

英文标题  Evaluating quickly method for DDoS attack on authority DNS service

中文标题  [一种快速评估DDoS攻击对DNS权威服务影响的方法](http://www.arocmag.com/article/01-2015-11-060.html)

Abstract: Authority DNS response success rate is decreasing when it suffer DDoS attack. But Different Domain’s query count may increase or decrease, because there are many difference on different Recursive DNS’s fail-retry policy , different domain’s RR TTL, different domain’s visit frequence, etc. We give a method to calc Authority DNS response success influence when DDoS attack  with history query log support. This method can quickly calculate the response success influence of each domain which serve by the Authority DNS when DDoS attack, by pass the query count’s sharply increase or decrease.
Key words: authority dns;recursive dns; domain; DDoS attack; DNS

# background

When TLD encounter DDoS attack, it's successful response rate of SLD NS will decrease.

There are many factors infected the TLD log in attack time, such as recursive resolver's retry policy, domain NS TTL, domain visit frequency, SLD's subdomain set.

We check TLD log of the attack time, some domain queries increased, but at the same time some domain queries decreased, different from normal case.

Increased queries: TLD not response in time, or response packets loss because of DDoS flow, widely used domain, all of them can cause large amount retry queries.

Decreased queries: Query Packets can not successful go to .CN TLD.

Therefore, we need an evaluating quickly method for DDoS attack on .CN TLD.

# source data

analyse .CN TLD log.

    { 
    time 2013-12-08 00:00:32
    src_ip 111.226.54.137
    domain xxx.cn
    qtype A
    src_country China
    src_province Hebei
    src_isp Telecom
    }

# evaluating method

isp recursive resolver, public recursive dns, some probe nodes send a relative stable amount of queries in normal case.

Therefore, we can check the trend of "historical stable queries" src_ip set, to evaluating the TLD service status.

## src_set

src_set(D, time_window, window_end_time) : in [window_end_time - time_window, window_end_time], all src_ip set that has query domain D.

time_window >= 2*TTL of domain D , because recursive will redo NS query after TTL expired.

## time_series

    time_series(end_time, time_gap, i) = end_time - (i-1)*time_gap

## common_src_set

    for i from 1 to N
    do
    T_i = time_series(end_time, time_gap, i)
    src_set_i = src_set(D, time_window, T_i)
    end for

    common_src_set = src_set_1 ∩  src_set_2 ∩  …  ∩ src_set_N
    common_src_num = length(common_src_set)

time_gap:

    0 < time_gap < time_window : i th window partial overlap i+1 th window, satisfied with long TTL domain D.
    time_gap == time_window : satisfied with short TTL domain D, and time_window >> 2*TTL
    time_gap > time_window : i th window not adjacent with i+1 th window, satisfied with histroy same day, for example, S=7day means that today vs last week same time.

## exists_common_src_set

    exists_common_src_set(D, time_window, window_end_time) = src_set(D, time_window, window_end_time) ∩ common_src_set
    exists_common_src_num = length(exists_common_src_set)
    exists_common_src_rate = exists_common_src_num / common_src_num

## ns_serv_domain_rate

in attack, [ attack_piece_time - time_window, attack_piece_time ]

    ns_serv_domain_rate  = exists_common_src_rate(D, time_window, attack_piece_time)

# additional parameters

## consider about src_ip's geolocation

src_set(D, time_window, window_end_time, country, province, isp)

## consider about query_count of domain D

only selecte domains that query_count(D) >= min_query_count into common_src_set 

ceiling the query_cnt > time_window/TTL

another choice, use query_count's median to calc rate

    qry_cnt_median_set = { qry_cnt_median(src_ip) | src_ip ∈ common_src_set }
    common_src_num = ∑ qry_cnt_median_set

    exists_qry_cnt _set = { qry_cnt (src_ip) | src_ip ∈ exists_common_src_set }
    exists_common_src_num = ∑ exists_qry_cnt _set

    exists_common_src_rate = exists_common_src_num / common_src_num
    ns_serv_domain_rate  = exists_common_src_rate

## consider about actual user number of each src_ip served


    serv_query_median_set = { serv_user_num(src_ip) * qry_cnt_median(src_ip) | src_ip ∈ common_src_set }
    common_src_num = ∑ serv_query_median_set

    exists_serv_query _set = { serv_user_num(src_ip) * qry_cnt (src_ip) | src_ip ∈ exists_common_src_set }
    exists_common_src_num = ∑ exists_serv_query _set

    exists_common_src_rate = exists_common_src_num / common_src_num
    ns_serv_domain_rate  = exists_common_src_rate

# analysis

.CN TLD attack occured at 2013.08.25

we select 5 days weibo.cn/t.cn query data from .CN TLD log, 2013.08.17/18/24/25/26

detail figures show in the paper.

# 中文摘要

拒绝服务攻击可能导致DNS权威服务器应答成功率下降。由于各地的递归服务器查询失败重试策略不同、域名TTL配置不同、域名访问频率不同等多个相关因素综合影响，从权威服务器日志可以观测到部分域名的查询量会上升，部分域名的查询量会下降。本文结合历史数据，提出了一种评估拒绝服务攻击对DNS权威服务影响的方法。该方法能够在DDoS攻击发生时，多个域名查询量同时上升下降的情况下，快速评估每个域名解析服务实际影响。
关键词:	权威服务器；递归服务器；域名；拒绝服务攻击; DNS

