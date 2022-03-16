//=====================================================================
//
// KCP - A Better ARQ Protocol Implementation
// skywind3000 (at) gmail.com, 2010-2011
//  
// Features:
// + Average RTT reduce 30% - 40% vs traditional ARQ like tcp.
// + Maximum RTT reduce three times vs tcp.
// + Lightweight, distributed as a single source file.
//
//=====================================================================
#include "ikcp.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>



//=====================================================================
// KCP BASIC
//=====================================================================
const IUINT32 IKCP_RTO_NDL = 30;		// no delay min rto
const IUINT32 IKCP_RTO_MIN = 100;		// normal min rto
const IUINT32 IKCP_RTO_DEF = 200;
const IUINT32 IKCP_RTO_MAX = 60000;
const IUINT32 IKCP_CMD_PUSH = 81;		// cmd: push data
const IUINT32 IKCP_CMD_ACK  = 82;		// cmd: ack
const IUINT32 IKCP_CMD_WASK = 83;		// cmd: window probe (ask)
const IUINT32 IKCP_CMD_WINS = 84;		// cmd: window size (tell)
const IUINT32 IKCP_ASK_SEND = 1;		// need to send IKCP_CMD_WASK
const IUINT32 IKCP_ASK_TELL = 2;		// need to send IKCP_CMD_WINS
const IUINT32 IKCP_WND_SND = 32;
const IUINT32 IKCP_WND_RCV = 128;       // must >= max fragment size，参见 ikcp_wndsize 函数，这个值可以认为是主动设定的接收窗口大小的下限
const IUINT32 IKCP_MTU_DEF = 1400;
const IUINT32 IKCP_ACK_FAST	= 3;
const IUINT32 IKCP_INTERVAL	= 100;
const IUINT32 IKCP_OVERHEAD = 24;
const IUINT32 IKCP_DEADLINK = 20;
const IUINT32 IKCP_THRESH_INIT = 2;
const IUINT32 IKCP_THRESH_MIN = 2;
const IUINT32 IKCP_PROBE_INIT = 7000;		// 7 secs to probe window size
const IUINT32 IKCP_PROBE_LIMIT = 120000;	// up to 120 secs to probe window
const IUINT32 IKCP_FASTACK_LIMIT = 5;		// max times to trigger fastack


//---------------------------------------------------------------------
// encode / decode
//---------------------------------------------------------------------

/* encode 8 bits unsigned int */
static inline char *ikcp_encode8u(char *p, unsigned char c)
{
	*(unsigned char*)p++ = c;
	return p;
}

/* decode 8 bits unsigned int */
static inline const char *ikcp_decode8u(const char *p, unsigned char *c)
{
	*c = *(unsigned char*)p++;
	return p;
}

/* encode 16 bits unsigned int (lsb) */
static inline char *ikcp_encode16u(char *p, unsigned short w)
{
#if IWORDS_BIG_ENDIAN || IWORDS_MUST_ALIGN
	*(unsigned char*)(p + 0) = (w & 255);
	*(unsigned char*)(p + 1) = (w >> 8);
#else
	memcpy(p, &w, 2);
#endif
	p += 2;
	return p;
}

/* decode 16 bits unsigned int (lsb) */
static inline const char *ikcp_decode16u(const char *p, unsigned short *w)
{
#if IWORDS_BIG_ENDIAN || IWORDS_MUST_ALIGN
	*w = *(const unsigned char*)(p + 1);
	*w = *(const unsigned char*)(p + 0) + (*w << 8);
#else
	memcpy(w, p, 2);
#endif
	p += 2;
	return p;
}

/* encode 32 bits unsigned int (lsb) */
static inline char *ikcp_encode32u(char *p, IUINT32 l)
{
#if IWORDS_BIG_ENDIAN || IWORDS_MUST_ALIGN
	*(unsigned char*)(p + 0) = (unsigned char)((l >>  0) & 0xff);
	*(unsigned char*)(p + 1) = (unsigned char)((l >>  8) & 0xff);
	*(unsigned char*)(p + 2) = (unsigned char)((l >> 16) & 0xff);
	*(unsigned char*)(p + 3) = (unsigned char)((l >> 24) & 0xff);
#else
	memcpy(p, &l, 4);
#endif
	p += 4;
	return p;
}

/* decode 32 bits unsigned int (lsb) */
static inline const char *ikcp_decode32u(const char *p, IUINT32 *l)
{
#if IWORDS_BIG_ENDIAN || IWORDS_MUST_ALIGN
	*l = *(const unsigned char*)(p + 3);
	*l = *(const unsigned char*)(p + 2) + (*l << 8);
	*l = *(const unsigned char*)(p + 1) + (*l << 8);
	*l = *(const unsigned char*)(p + 0) + (*l << 8);
#else 
	memcpy(l, p, 4);
#endif
	p += 4;
	return p;
}

static inline IUINT32 _imin_(IUINT32 a, IUINT32 b) {
	return a <= b ? a : b;
}

static inline IUINT32 _imax_(IUINT32 a, IUINT32 b) {
	return a >= b ? a : b;
}

static inline IUINT32 _ibound_(IUINT32 lower, IUINT32 middle, IUINT32 upper) 
{
	return _imin_(_imax_(lower, middle), upper);
}

static inline long _itimediff(IUINT32 later, IUINT32 earlier) 
{
	return ((IINT32)(later - earlier));
}

//---------------------------------------------------------------------
// manage segment
//---------------------------------------------------------------------
typedef struct IKCPSEG IKCPSEG;

static void* (*ikcp_malloc_hook)(size_t) = NULL;
static void (*ikcp_free_hook)(void *) = NULL;

// internal malloc
static void* ikcp_malloc(size_t size) {
	if (ikcp_malloc_hook) 
		return ikcp_malloc_hook(size);
	return malloc(size);
}

// internal free
static void ikcp_free(void *ptr) {
	if (ikcp_free_hook) {
		ikcp_free_hook(ptr);
	}	else {
		free(ptr);
	}
}

// redefine allocator
void ikcp_allocator(void* (*new_malloc)(size_t), void (*new_free)(void*))
{
	ikcp_malloc_hook = new_malloc;
	ikcp_free_hook = new_free;
}

// allocate a new kcp segment
// 分配一块 KCP segment 的内存空间，其中 size 用于指示数据部分的大小
static IKCPSEG* ikcp_segment_new(ikcpcb *kcp, int size)
{
	return (IKCPSEG*)ikcp_malloc(sizeof(IKCPSEG) + size);
}

// delete a segment
static void ikcp_segment_delete(ikcpcb *kcp, IKCPSEG *seg)
{
	ikcp_free(seg);
}

// write log
void ikcp_log(ikcpcb *kcp, int mask, const char *fmt, ...)
{
	char buffer[1024];
	va_list argptr;
	if ((mask & kcp->logmask) == 0 || kcp->writelog == 0) return;
	va_start(argptr, fmt);
	vsprintf(buffer, fmt, argptr);
	va_end(argptr);
	kcp->writelog(buffer, kcp, kcp->user);
}

// check log mask
static int ikcp_canlog(const ikcpcb *kcp, int mask)
{
	if ((mask & kcp->logmask) == 0 || kcp->writelog == NULL) return 0;
	return 1;
}

// output segment
// 本端通过调用本函数，可以将 size 个字节的数据发送出去
// 注意 KCP 本身不定义下层数据包的发送方式，而是通过 callback 方式调用 kcp->output 来完成发送
static int ikcp_output(ikcpcb *kcp, const void *data, int size)
{
	assert(kcp);
	assert(kcp->output);
	if (ikcp_canlog(kcp, IKCP_LOG_OUTPUT)) {
		ikcp_log(kcp, IKCP_LOG_OUTPUT, "[RO] %ld bytes", (long)size);
	}
	if (size == 0) return 0;
	return kcp->output((const char*)data, size, kcp, kcp->user);
}

// output queue
void ikcp_qprint(const char *name, const struct IQUEUEHEAD *head)
{
#if 0
	const struct IQUEUEHEAD *p;
	printf("<%s>: [", name);
	for (p = head->next; p != head; p = p->next) {
		const IKCPSEG *seg = iqueue_entry(p, const IKCPSEG, node);
		printf("(%lu %d)", (unsigned long)seg->sn, (int)(seg->ts % 10000));
		if (p->next != head) printf(",");
	}
	printf("]\n");
#endif
}


//---------------------------------------------------------------------
// create a new kcpcb
//---------------------------------------------------------------------
ikcpcb* ikcp_create(IUINT32 conv, void *user)
{
	ikcpcb *kcp = (ikcpcb*)ikcp_malloc(sizeof(struct IKCPCB));
	if (kcp == NULL) return NULL;
	kcp->conv = conv;
	kcp->user = user;
	kcp->snd_una = 0;
	kcp->snd_nxt = 0;
	kcp->rcv_nxt = 0;
	kcp->ts_recent = 0;
	kcp->ts_lastack = 0;
	kcp->ts_probe = 0;
	kcp->probe_wait = 0;
	kcp->snd_wnd = IKCP_WND_SND;
	kcp->rcv_wnd = IKCP_WND_RCV;
	kcp->rmt_wnd = IKCP_WND_RCV;
	kcp->cwnd = 0;
	kcp->incr = 0;
	kcp->probe = 0;
	kcp->mtu = IKCP_MTU_DEF; // 一个链路层帧所能承载的所能承载的最大数据量叫做最大传送单元（MTU，以字节为单位）
	kcp->mss = kcp->mtu - IKCP_OVERHEAD;
	kcp->stream = 0;

	kcp->buffer = (char*)ikcp_malloc((kcp->mtu + IKCP_OVERHEAD) * 3);
	if (kcp->buffer == NULL) {
		ikcp_free(kcp);
		return NULL;
	}

	iqueue_init(&kcp->snd_queue); // 初始化发送队列，注意发送队列是 segment 的队列，而 kcp->snd_queue 在双向链表中是一个无意义的头结点
	iqueue_init(&kcp->rcv_queue); // 初始化接收队列
	iqueue_init(&kcp->snd_buf);
	iqueue_init(&kcp->rcv_buf);
	kcp->nrcv_buf = 0;
	kcp->nsnd_buf = 0;
	kcp->nrcv_que = 0;
	kcp->nsnd_que = 0;
	kcp->state = 0;
	kcp->acklist = NULL;
	kcp->ackblock = 0;
	kcp->ackcount = 0;
	kcp->rx_srtt = 0;
	kcp->rx_rttval = 0;
	kcp->rx_rto = IKCP_RTO_DEF;
	kcp->rx_minrto = IKCP_RTO_MIN;
	kcp->current = 0;
	kcp->interval = IKCP_INTERVAL;
	kcp->ts_flush = IKCP_INTERVAL;
	kcp->nodelay = 0;
	kcp->updated = 0;
	kcp->logmask = 0;
	kcp->ssthresh = IKCP_THRESH_INIT;
	kcp->fastresend = 0;
	kcp->fastlimit = IKCP_FASTACK_LIMIT;
	kcp->nocwnd = 0;
	kcp->xmit = 0;
	kcp->dead_link = IKCP_DEADLINK;
	kcp->output = NULL;
	kcp->writelog = NULL;

	return kcp;
}


//---------------------------------------------------------------------
// release a new kcpcb
//---------------------------------------------------------------------
void ikcp_release(ikcpcb *kcp)
{
	assert(kcp);
	if (kcp) {
		IKCPSEG *seg;
		while (!iqueue_is_empty(&kcp->snd_buf)) {
			seg = iqueue_entry(kcp->snd_buf.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		while (!iqueue_is_empty(&kcp->rcv_buf)) {
			seg = iqueue_entry(kcp->rcv_buf.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		while (!iqueue_is_empty(&kcp->snd_queue)) {
			seg = iqueue_entry(kcp->snd_queue.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		while (!iqueue_is_empty(&kcp->rcv_queue)) {
			seg = iqueue_entry(kcp->rcv_queue.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		if (kcp->buffer) {
			ikcp_free(kcp->buffer);
		}
		if (kcp->acklist) {
			ikcp_free(kcp->acklist);
		}

		kcp->nrcv_buf = 0;
		kcp->nsnd_buf = 0;
		kcp->nrcv_que = 0;
		kcp->nsnd_que = 0;
		kcp->ackcount = 0;
		kcp->buffer = NULL;
		kcp->acklist = NULL;
		ikcp_free(kcp);
	}
}


//---------------------------------------------------------------------
// set output callback, which will be invoked by kcp
//---------------------------------------------------------------------
void ikcp_setoutput(ikcpcb *kcp, int (*output)(const char *buf, int len,
	ikcpcb *kcp, void *user))
{
	kcp->output = output;
}


//---------------------------------------------------------------------
// user/upper level recv: returns size, returns below zero for EAGAIN
// 上层应用可以通过调用该函数来接收数据
// 因为数据会直接写入到 buffer 中，因此调用前需要分配足够的空间，这里用 len 来指示 buffer 的空间大小
//---------------------------------------------------------------------
int ikcp_recv(ikcpcb *kcp, char *buffer, int len)
{
	struct IQUEUEHEAD *p;
	int ispeek = (len < 0)? 1 : 0; // 如果 len 为负数，则表示上层只是想简单探测一下目前在接收队列里的情况
	int peeksize;
	int recover = 0;
	IKCPSEG *seg;
	assert(kcp);

	if (iqueue_is_empty(&kcp->rcv_queue))
		return -1;

	if (len < 0) len = -len;

	peeksize = ikcp_peeksize(kcp); // 简单探测在当前接收队列中，属于第一条消息的所有 segment 的数据部分的总长度

	if (peeksize < 0) // 如果简单探测就发现有错误，直接返回
		return -2; // 这里返回 -2 表明接收队列里的 segment 们的数据部分无法组成一条完整的消息

	if (peeksize > len) // 上层给的 buffer 的大小（即 len 值）太小，存储不下一条完整的消息，这里请注意传入的 len 值为负的情况
		return -3; // 这种情况返回 -3

	// 目前还没有从接收队列中取出对应的 segment 拼接并交付上层
	// 目前的状态是接收队列满，因此本次数据交付完之后，接收队列中有可能出现空位
	// 因此要做一个标记，如果之后取完数据之后，接收队列有了空位，那么应当主动告知对方（远端）我这里有空位了，你可以发送新的 segment 过来
	if (kcp->nrcv_que >= kcp->rcv_wnd)
		recover = 1; // 标记窗口可以恢复

	// merge fragment
	// 将多个 segment 所承载的 fragment 拼接起来，组成一条完整的消息
	for (len = 0, p = kcp->rcv_queue.next; p != &kcp->rcv_queue; ) { // 从接收队列的队头开始遍历
		int fragment;
		seg = iqueue_entry(p, IKCPSEG, node); // 根据队列的节点获取当前的 segment
		p = p->next;

		if (buffer) {
			memcpy(buffer, seg->data, seg->len); // 将 segment 的数据部分拷贝到 buffer 中，即将数据交付给上层
			buffer += seg->len;
		}

		len += seg->len;
		fragment = seg->frg; // 记录下当前 segment 所承载的这个 fragment 的编号

		if (ikcp_canlog(kcp, IKCP_LOG_RECV)) {
			ikcp_log(kcp, IKCP_LOG_RECV, "recv sn=%lu", (unsigned long)seg->sn); // 打印日志
		}

		if (ispeek == 0) { // 上层不是想要简单探测一下，说明上层是要实实在在接收消息（接收报文）
			iqueue_del(&seg->node); // 从队列中拆下当前 segment 对应的节点
			ikcp_segment_delete(kcp, seg); // 释放当前 segment 的空间
			kcp->nrcv_que--; // 接收队列的 segment 数目减一
		}

		if (fragment == 0) // 遇到一条消息的末尾 fragment 即退出对接收队列的遍历
			break;
	}

	assert(len == peeksize);

	// move available data from rcv_buf -> rcv_queue
	// 因为接收队列可能产生了新的空位，因此需要尝试从接收缓存往接收队列中转移节点
	while (! iqueue_is_empty(&kcp->rcv_buf)) {
		seg = iqueue_entry(kcp->rcv_buf.next, IKCPSEG, node); // 获取接收缓存里的首个 segment

		// 根据 sn 字段来确保 segment 是严格按序转移到接收队列当中的，这里 kcp->rcv_nxt 表示当前接收队列的待接收 segment 的序号
		// 根据接收队列中的 segment 数量，以及接收窗口的大小，来判断是否还能往接收队列中转移 segment
		if (seg->sn == kcp->rcv_nxt && kcp->nrcv_que < kcp->rcv_wnd) {
			iqueue_del(&seg->node); // 从接收缓存中拆下当前 segment 对应的节点
			kcp->nrcv_buf--; // 接收缓存的 segment 数目减一
			iqueue_add_tail(&seg->node, &kcp->rcv_queue); // 在接收队列的尾部插入该 segment 对应的节点
			kcp->nrcv_que++; // 接收队列的 segment 数目加一
			kcp->rcv_nxt++;
		}	else {
			break;
		}
	}

	// fast recover
	// 向上层交付前接收队列为满（即 recover 标记），交付完之后接收队列又有了空位，则应主动告知对方（远端）我这里的接收队列有空位产生
	if (kcp->nrcv_que < kcp->rcv_wnd && recover) {
		// ready to send back IKCP_CMD_WINS in ikcp_flush
		// tell remote my window size
		// kcp->probe 是一个关于窗口的探查控制变量，如果 kcp->probe 的 IKCP_ASK_TELL 位置 1，表明要告知对方（远端）我的接收队列有空位产生
		// 注意 kcp->rcv_wnd 是接收队列的节点数上限，kcp->nrcv_que 是接收队列的当前节点数目，剩余容量（空位数目）是两者的差值
		kcp->probe |= IKCP_ASK_TELL; // 对 kcp->probe 的 IKCP_ASK_TELL 位置 1
	}

	return len; // 返回接收队列中首条消息（接收队列里的前面若干个 segment 的数据部分组成的一条完整消息）的长度
	// 如果上层调用只是想简单探测，那么接收队列不会有改变
	// 如果上层调用确实想要接收一条完整的消息（报文），那么组成该条消息的前若干个 segment 会被删除，对应的数据会按序填入到 buffer 中
}


//---------------------------------------------------------------------
// peek data size
// 简单探测一下当前接收队列中第一条消息（报文）的数据总长度（以字节为单位）
// 注意在发送端可能会将一条较长的消息切分成多个 fragment，每个 fragment 交由一个 segment 来承载
// 如果接收队列为空，或者接收队列中的 segment 不足以组成一条完整的消息，则返回 -1 表示有错误
//---------------------------------------------------------------------
int ikcp_peeksize(const ikcpcb *kcp)
{
	struct IQUEUEHEAD *p;
	IKCPSEG *seg;
	int length = 0;

	assert(kcp);

	if (iqueue_is_empty(&kcp->rcv_queue)) return -1;

	seg = iqueue_entry(kcp->rcv_queue.next, IKCPSEG, node); // 获取接收队列的队头 segment
	if (seg->frg == 0) return seg->len; // 如果该 segment 的 frg 编号是 0，则表明它是一条消息的最后一个 fragment

	if (kcp->nrcv_que < seg->frg + 1) return -1; // 接收队列中 segment 的数量必须大于队头 segment 的 frg 编号，这样队列中的 fragment 们才能组成一条完整的消息

	for (p = kcp->rcv_queue.next; p != &kcp->rcv_queue; p = p->next) { // 从头到尾遍历接收队列
		seg = iqueue_entry(p, IKCPSEG, node);
		length += seg->len; // 对每个 segment 的数据部分长度做累计
		if (seg->frg == 0) break; // 直到遇到某条消息的最后一个 fragment 就结束遍历
	}

	return length;
}


//---------------------------------------------------------------------
// user/upper level send, returns below zero for error
// 上层应用可以通过调用该函数来发送数据
// 实际上主要是将 buffer 中的数据打包成一个或多个 segment 添加到发送队列的队尾
//---------------------------------------------------------------------
int ikcp_send(ikcpcb *kcp, const char *buffer, int len)
{
	IKCPSEG *seg;
	int count, i;

	assert(kcp->mss > 0);
	if (len < 0) return -1;

	// append to previous segment in streaming mode (if possible)
	if (kcp->stream != 0) { // kcp->stream 标记是否采用流传输模式
		if (!iqueue_is_empty(&kcp->snd_queue)) {
			IKCPSEG *old = iqueue_entry(kcp->snd_queue.prev, IKCPSEG, node); // 获取发送队列的队尾 KCP segment
			if (old->len < kcp->mss) { // KCP segment 的 len 字段给出该 segment 的数据部分长度，满足该条件表明 old 这个 segment 还可以放入数据
				int capacity = kcp->mss - old->len; // 计算 old 这个 segment 的数据部分的剩余容量
				int extend = (len < capacity)? len : capacity; // 计算 old 这个 segment 的数据部分需要进一步扩展的大小
				seg = ikcp_segment_new(kcp, old->len + extend); // 新建一个 KCP segment 来替换原来的 old segment
				assert(seg);
				if (seg == NULL) {
					return -2;
				}
				iqueue_add_tail(&seg->node, &kcp->snd_queue); // 将新建的 KCP segment 添加到发送队列 kcp->snd_queue 的队尾
				memcpy(seg->data, old->data, old->len); // 将 old segment 的数据部分拷贝到新 segment 中
				if (buffer) {
					memcpy(seg->data + old->len, buffer, extend); // 将待发送数据 buffer 中的前 extend 个字节拷贝到新 segment 中（放在 old segment 数据的后面）
					buffer += extend;
				}
				seg->len = old->len + extend;
				seg->frg = 0;
				len -= extend; // 此时 len 变为指示剩余还有多少字节没有被打包成 segment
				iqueue_del_init(&old->node); // 从队列中拆下 old segment 对应的节点
				ikcp_segment_delete(kcp, old); // 将 old segment 释放
			}
		}
		if (len <= 0) { // 如果没有剩余数据了就直接返回
			return 0;
		}
	}

	// 计算（剩余）数据需要多少个 segment 来承载
	if (len <= (int)kcp->mss) count = 1;
	else count = (len + kcp->mss - 1) / kcp->mss;

	if (count >= (int)IKCP_WND_RCV) return -2;

	if (count == 0) count = 1;

	// fragment
	// 将当前这条消息（message，应用层报文），即 buffer 中的 size 个字节，拆分成多个 fragment，每个 fragment 交由一个 segment 承载
	for (i = 0; i < count; i++) {
		int size = len > (int)kcp->mss ? (int)kcp->mss : len; // 当前 fragment 的大小，即当前 segment 的数据部分的大小
		seg = ikcp_segment_new(kcp, size); // 为当前的 segment 分配空间
		assert(seg);
		if (seg == NULL) {
			return -2;
		}
		if (buffer && len > 0) {
			memcpy(seg->data, buffer, size); // 将 buffer 中的 size 个字节拷贝到当前 segment 的数据部分中
		}
		seg->len = size; // 记录当前 segment 的数据部分的长度
		seg->frg = (kcp->stream == 0)? (count - i - 1) : 0; // 为当前 segment 所承载的 fragment 一个编号，该编号从大到小布置（最后一个 fragment 的 frg 编号为 0）
		// 这里值得注意的是，如果是流传输模式，每个 segment 的 frg 编号都是 0，可以看做是流传输模式下每个 segment 都自成一条消息
		iqueue_init(&seg->node);
		iqueue_add_tail(&seg->node, &kcp->snd_queue); // 将当前 segment 添加到发送队列的队尾
		kcp->nsnd_que++; // kcp->nsnd_que 标记发送队列中 segment 的数量
		if (buffer) {
			buffer += size;
		}
		len -= size;
	}

	return 0;
}


//---------------------------------------------------------------------
// parse ack
//---------------------------------------------------------------------
static void ikcp_update_ack(ikcpcb *kcp, IINT32 rtt)
{
	IINT32 rto = 0;
	if (kcp->rx_srtt == 0) {
		kcp->rx_srtt = rtt;
		kcp->rx_rttval = rtt / 2;
	}	else {
		long delta = rtt - kcp->rx_srtt;
		if (delta < 0) delta = -delta;
		kcp->rx_rttval = (3 * kcp->rx_rttval + delta) / 4;
		kcp->rx_srtt = (7 * kcp->rx_srtt + rtt) / 8;
		if (kcp->rx_srtt < 1) kcp->rx_srtt = 1;
	}
	rto = kcp->rx_srtt + _imax_(kcp->interval, 4 * kcp->rx_rttval);
	kcp->rx_rto = _ibound_(kcp->rx_minrto, rto, IKCP_RTO_MAX);
}

/**
 * 根据发送缓存的状态，更新 kcp->snd_una 的值
 * kcp->snd_una 表示最早未确认 segment 的序号，只能向后移动
 * 这里的 kcp->snd_una 类似于 Go-Back-N 协议中的基序号（base）变量，参见《计算机网络 自顶向下方法 第七版》
 */
static void ikcp_shrink_buf(ikcpcb *kcp)
{
	// 注意，区间 [kcp->snd_una, kcp->snd_nxt) 标明了本端的发送缓存的序号范围
	// kcp->snd_una 是最早未确认 segment 的序号，即发送缓存中的首个 segment 的序号，在 kcp->snd_una 序号之前的 segment 都已经被远端确认过，应当及时从发送缓存中删除

	struct IQUEUEHEAD *p = kcp->snd_buf.next; // 将指针 p 初始化定位到发送缓存中首个节点的位置
	if (p != &kcp->snd_buf) { // 如果发送缓存不为空
		IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node); // 得到发送缓存的首个节点对应的 segment
		kcp->snd_una = seg->sn; // 将 kcp->snd_una 设定为该 segment 的序号
	}	else { // 如果发送缓存为空
		kcp->snd_una = kcp->snd_nxt; // kcp->snd_nxt 是发送缓存下一个要使用的序号，是发送端的最小未使用序号，如果发送缓存为空那么 kcp->snd_una 应当等于 kcp->snd_nxt
	}
}

/**
 * 根据一个确认号，尝试删除掉发送缓存中的某个 segment
 */
static void ikcp_parse_ack(ikcpcb *kcp, IUINT32 sn)
{
	struct IQUEUEHEAD *p, *next;

	if (_itimediff(sn, kcp->snd_una) < 0 || _itimediff(sn, kcp->snd_nxt) >= 0) // 如果确认的 segment 的序号在发送缓存的序号范围 [snd_una, snd_nxt) 之外
		return; // 确认不了任何 segment

	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = next) { // 从头到尾遍历发送缓存
		IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node); // 获取当前节点对应的 segment
		next = p->next;
		if (sn == seg->sn) { // 如果当前这个 segment 是受到确认的那个 segment
			iqueue_del(p); // 从发送缓存中拆下该节点
			ikcp_segment_delete(kcp, seg); // 释放该 segment 的空间
			kcp->nsnd_buf--; // 发送缓存的节点数自减一
			break; // 直接跳出循环，因为一次只可能确认一个 segment
		}
		if (_itimediff(sn, seg->sn) < 0) {
			break;
		}
	}
}

/**
 * 根据从远端接收到的 una 字段值（累计确认）维护己方的发送缓存，将受到确认的 segment 全部从发送缓存中删除
 */
static void ikcp_parse_una(ikcpcb *kcp, IUINT32 una)
{
	struct IQUEUEHEAD *p, *next;
	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = next) { // 从头到尾遍历发送缓存
		IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node); // 根据发送缓存的节点，解析出对应的当前 segment
		next = p->next;
		if (_itimediff(una, seg->sn) > 0) { // 如果累计确认 una 大于当前 segment 的序号，说明当前 segment 已经被对方（远端）确认接收
			iqueue_del(p); // 从发送缓存中拆下当前 segment 所对应的节点
			ikcp_segment_delete(kcp, seg); // 释放当前 segment 的空间
			kcp->nsnd_buf--; // 发送缓存的节点数自减一
		}	else {
			break; // 由于发送缓存中的 segment 的序号是逐渐增大的，所以一旦遇到第一个没被确认的 segment 就可以跳出遍历
		}
	}
}

static void ikcp_parse_fastack(ikcpcb *kcp, IUINT32 sn, IUINT32 ts)
{
	struct IQUEUEHEAD *p, *next;

	if (_itimediff(sn, kcp->snd_una) < 0 || _itimediff(sn, kcp->snd_nxt) >= 0)
		return;

	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = next) {
		IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
		next = p->next;
		if (_itimediff(sn, seg->sn) < 0) {
			break;
		}
		else if (sn != seg->sn) {
		#ifndef IKCP_FASTACK_CONSERVE
			seg->fastack++;
		#else
			if (_itimediff(ts, seg->ts) >= 0)
				seg->fastack++;
		#endif
		}
	}
}


//---------------------------------------------------------------------
// ack append
// 将 sn 和 ts 组成的一个 ack 放入当本端的 acklist 中，等待发送
//---------------------------------------------------------------------
static void ikcp_ack_push(ikcpcb *kcp, IUINT32 sn, IUINT32 ts)
{
	IUINT32 newsize = kcp->ackcount + 1; // ackcount 表示 acklist 中 ack 的数量，newsize 即新增当前这个 ack 之后新的数量
	IUINT32 *ptr;
	
	// 注意 acklist 是指针类型，它需要分配足够的空间后才能存储 ack，如果目前分配的空间大小不足以放入的这个新的 ack 就要增长空间 
	// ackblock 给定了当前 acklist 中能存储的 ack 的数量上限，换句话说就是 ackblock 指明了当前 acklist 分配的空间大小
	if (newsize > kcp->ackblock) {
		// 可以看到，acklist 是一个可增长的数组，基于指针配合 malloc 和 free 来实现数组的增长

		IUINT32 *acklist; // 这将会是新的 acklist
		IUINT32 newblock; // 这个变量会指明新的 acklist 的应当分配空间的大小

		for (newblock = 8; newblock < newsize; newblock <<= 1); // 选定一个合适的 newblock 值，注意 newblock 一定不会小于 newsize
		acklist = (IUINT32*)ikcp_malloc(newblock * sizeof(IUINT32) * 2); // 根据 newblock 值，为新的 acklist 分配空间，注意分配空间的大小

		if (acklist == NULL) {
			assert(acklist != NULL);
			abort();
		}

		if (kcp->acklist != NULL) {
			// 将旧的 acklist 里的值都拷贝到新的 acklist 中来
			IUINT32 x;
			for (x = 0; x < kcp->ackcount; x++) {
				acklist[x * 2 + 0] = kcp->acklist[x * 2 + 0];
				acklist[x * 2 + 1] = kcp->acklist[x * 2 + 1];
			}
			ikcp_free(kcp->acklist); // 释放掉旧的 acklist 的空间
		}

		kcp->acklist = acklist; // 新的 acklist 替代掉旧的 acklist
		kcp->ackblock = newblock; // 以及更新相应的 ackblock 值
	}

	ptr = &kcp->acklist[kcp->ackcount * 2]; // 根据 ackcount 定位到 acklist 中，当前这个新加入的 ack 应存放的位置
	ptr[0] = sn; // 先放入序号，在 ack 中该序号的含义就是确认号，即向对方确认我方收到了你发来的序号为 sn 的 segment
	ptr[1] = ts; // 再放入时间戳，在 ack 中该时间戳就是对方发来的 segment 的时间戳，也就是对方发送这个 segment 时的时间点
	kcp->ackcount++;
}

/**
 * 将 KCP 的 acklist 中保存的第 p 个 ack 写入到 sn 和 ts 中 
 */
static void ikcp_ack_get(const ikcpcb *kcp, int p, IUINT32 *sn, IUINT32 *ts)
{
	if (sn) sn[0] = kcp->acklist[p * 2 + 0];
	if (ts) ts[0] = kcp->acklist[p * 2 + 1];
}


//---------------------------------------------------------------------
// parse data
// 尝试将新接收到的 segment 插入到接收缓存之中
// 由于接收缓存可能产生了变化，因此还会尝试从接收缓存往接收队列转移节点
//---------------------------------------------------------------------
void ikcp_parse_data(ikcpcb *kcp, IKCPSEG *newseg)
{
	struct IQUEUEHEAD *p, *prev;
	IUINT32 sn = newseg->sn; // 获取这个新来的 segment 的序号
	int repeat = 0;
	
	// 这里 kcp->rcv_nxt 表示当前接收队列的待接收 segment 的序号，kcp->rcv_wnd 是接收队列的节点数上限
	// 接收队列中 segment 严格保证序号逐个递增，接收队列的节点数是 kcp->nrcv_que，其上限是 kcp->rcv_wnd
	// 接收缓存相当于在接收队列之后，又划定了一块大小为 kcp->rcv_wnd 的区域，即区间 [kcp->rcv_nxt, kcp->rcv_nxt + kcp->rcv_wnd)，其中也是按序号递增存放 segment，但序号可以不连续
	if (_itimediff(sn, kcp->rcv_nxt + kcp->rcv_wnd) >= 0 ||
		_itimediff(sn, kcp->rcv_nxt) < 0) { // 如果接收到的新 segment 的序号不在为接收缓存所划定的区间 [kcp->rcv_nxt, kcp->rcv_nxt + kcp->rcv_wnd) 之内
		ikcp_segment_delete(kcp, newseg); // 直接释放掉这个新 segment 的空间
		return;
	}

	for (p = kcp->rcv_buf.prev; p != &kcp->rcv_buf; p = prev) { // 从尾往头遍历接收缓存，这里需要注意遍历顺序，以及接收队列和接收缓存的区别
		IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
		prev = p->prev;
		if (seg->sn == sn) { // 如果在接收缓存里发现重复的 segment
			repeat = 1;
			break;
		}
		if (_itimediff(sn, seg->sn) > 0) { // 从尾往头遍历接收缓存时，segment 的序号是逐渐减小的
			break; // 此时接收缓存里的这个 segment 已经比新 segment 的序号小了，再往前那些 segment 只会更小，所以直接跳出
		}
	}

	if (repeat == 0) { // 如果在接收缓存里没有发现重复
		iqueue_init(&newseg->node);
		iqueue_add(&newseg->node, p); // 那么在这个适当位置（即 p 的后面）插入当前这个 segment
		kcp->nrcv_buf++; // 接收缓存的大小自增一
	}	else { // 在接收缓存里发现了重复，就应当丢弃这个新来的 segment
		ikcp_segment_delete(kcp, newseg); // 释放这个新 segment 的空间
	}

#if 0
	ikcp_qprint("rcvbuf", &kcp->rcv_buf);
	printf("rcv_nxt=%lu\n", kcp->rcv_nxt);
#endif

	// move available data from rcv_buf -> rcv_queue
	// 尝试从接收缓存往接收队列转移节点，参考 ikcp_recv 函数里的注释解释
	while (! iqueue_is_empty(&kcp->rcv_buf)) {
		IKCPSEG *seg = iqueue_entry(kcp->rcv_buf.next, IKCPSEG, node);
		if (seg->sn == kcp->rcv_nxt && kcp->nrcv_que < kcp->rcv_wnd) {
			iqueue_del(&seg->node);
			kcp->nrcv_buf--;
			iqueue_add_tail(&seg->node, &kcp->rcv_queue);
			kcp->nrcv_que++;
			kcp->rcv_nxt++;
		}	else {
			break;
		}
	}

#if 0
	ikcp_qprint("queue", &kcp->rcv_queue);
	printf("rcv_nxt=%lu\n", kcp->rcv_nxt);
#endif

#if 1
//	printf("snd(buf=%d, queue=%d)\n", kcp->nsnd_buf, kcp->nsnd_que);
//	printf("rcv(buf=%d, queue=%d)\n", kcp->nrcv_buf, kcp->nrcv_que);
#endif
}


//---------------------------------------------------------------------
// input data
// KCP 本端通过该函数来收取来自下层的数据，会从 data 中读取 size 个字节
//---------------------------------------------------------------------
int ikcp_input(ikcpcb *kcp, const char *data, long size)
{
	IUINT32 prev_una = kcp->snd_una; // 接收到当前这个 segment 之前，记录下最早未确认 segment 的序号，即本端发送缓存的首个 segment 的序号
	IUINT32 maxack = 0, latest_ts = 0;
	int flag = 0;

	if (ikcp_canlog(kcp, IKCP_LOG_INPUT)) {
		ikcp_log(kcp, IKCP_LOG_INPUT, "[RI] %d bytes", (int)size);
	}

	if (data == NULL || (int)size < (int)IKCP_OVERHEAD) return -1;

	while (1) {
		IUINT32 ts, sn, len, una, conv;
		IUINT16 wnd;
		IUINT8 cmd, frg;
		IKCPSEG *seg;

		if (size < (int)IKCP_OVERHEAD) break;

		data = ikcp_decode32u(data, &conv); // 解码出 conv 字段，conv 唯一标识一个会话
		if (conv != kcp->conv) return -1; // 接收到的 segment 的 conv 必须和当前 kcp 的 conv 相同

		data = ikcp_decode8u(data, &cmd); // 解码出 cmd 字段，cmd 用于指示 segment 的类型，共有四种类型：数据类型 segment、ACK segment、询问窗口 segment、告知窗口 segment
		data = ikcp_decode8u(data, &frg); // 解码出 frg 字段，一个消息（报文）拆分成多个 fragment，每个 fragment 安排一个 frg 编号，从大到小安排，最后一个 fragment 编号为 0
		data = ikcp_decode16u(data, &wnd); // 解码出 wnd 字段，表示剩余接收窗口的大小（剩余窗口的大小 = 接收窗口大小 - 接收队列大小）
		data = ikcp_decode32u(data, &ts); // 解码出 ts 字段，时间戳
		data = ikcp_decode32u(data, &sn); // 解码出 sn 字段，即 sequence number 的缩写，序号字段，表示当前 segment 的序号
		data = ikcp_decode32u(data, &una); // 解码出 una 字段，即 expected sequence number，期待接收的下一个 segment 的序号，累计确认所有序号小于 una 的 segment 都已收到，类似于 TCP 的确认号字段
		data = ikcp_decode32u(data, &len); // 解码出 len 字段，即 segment 中数据部分的长度，单位为字节
		// 不难看出，KCP segment 首部共有 8 个字段，总计 32 + 8 + 8 + 16 + 32 * 4 = 32 * 6 个比特，即 24 个字节

		size -= IKCP_OVERHEAD; // 计算剩余的字节数

		if ((long)size < (long)len || (int)len < 0) return -2; // 根据当前 segment 的数据部分的字节数 len 做检查

		if (cmd != IKCP_CMD_PUSH && cmd != IKCP_CMD_ACK &&
			cmd != IKCP_CMD_WASK && cmd != IKCP_CMD_WINS) // 无法识别 cmd 字段
			return -3;

		kcp->rmt_wnd = wnd; // remote window，记录下远端的（剩余）接收窗口的大小

		ikcp_parse_una(kcp, una); // 根据 una 字段的累计确认性质，删除掉发送缓存的前面若干个 segment
		ikcp_shrink_buf(kcp); // 删掉了 segment 之后，要更新 kcp->snd_una 的值
		// 参考《计算机网络 自顶向下方法 第七版》的 Go-Back-N 协议（滑动窗口协议），上面这两步就是己方的发送窗口的左沿（base）向右移动的过程

		if (cmd == IKCP_CMD_ACK) { // 接收到 ACK 类型的 segment，表示远端对本端发送过去的某个 segment 回复过来的一个确认

			if (_itimediff(kcp->current, ts) >= 0) { // 根据当前时间 kcp->current 和时间戳字段 ts 计算 ###################### TODO ######################
				ikcp_update_ack(kcp, _itimediff(kcp->current, ts));
			}

			ikcp_parse_ack(kcp, sn); // 传入当前接收到的 segment 的序号字段，由于是 ACK 类型，因此此时 sn 是确认号，尝试删除掉发送缓存中的某一个被确认的 segment
			ikcp_shrink_buf(kcp); // 删除掉的有可能是发送缓存的首个 segment，因此要维护一下 kcp->snd_una

			if (flag == 0) {
				flag = 1; // 执行快速重传的标记
				maxack = sn; // ###################### TODO ######################
				latest_ts = ts; // ###################### TODO ######################
			}	else {
				if (_itimediff(sn, maxack) > 0) {
				#ifndef IKCP_FASTACK_CONSERVE
					maxack = sn;
					latest_ts = ts;
				#else
					if (_itimediff(ts, latest_ts) > 0) {
						maxack = sn;
						latest_ts = ts;
					}
				#endif
				}
			}

			if (ikcp_canlog(kcp, IKCP_LOG_IN_ACK)) { // ###################### TODO ######################
				ikcp_log(kcp, IKCP_LOG_IN_ACK, 
					"input ack: sn=%lu rtt=%ld rto=%ld", (unsigned long)sn, 
					(long)_itimediff(kcp->current, ts),
					(long)kcp->rx_rto);
			}
		}
		else if (cmd == IKCP_CMD_PUSH) { // 接收到传输数据类型的 segment
			if (ikcp_canlog(kcp, IKCP_LOG_IN_DATA)) {
				ikcp_log(kcp, IKCP_LOG_IN_DATA, 
					"input psh: sn=%lu ts=%lu", (unsigned long)sn, (unsigned long)ts);
			}

			// 为接收缓存所划定的区间是 [kcp->rcv_nxt, kcp->rcv_nxt + kcp->rcv_wnd)，注意在整数域下的左闭右开
			if (_itimediff(sn, kcp->rcv_nxt + kcp->rcv_wnd) < 0) { // 接收到的这个新 segment 的序号没超出接收缓存的区间右边界
				ikcp_ack_push(kcp, sn, ts); // 需要返回给对方（远端）一个确认，将收到的数据 segment 的序号和时间戳组成一个 ack 放入到 kcp 的 acklist 中
				if (_itimediff(sn, kcp->rcv_nxt) >= 0) { // 接收到的这个新 segment 的序号也没有超出接收缓存的区间左边界
					// 此时这个新 segment 落在接收缓存的区间内
					seg = ikcp_segment_new(kcp, len); // 根据这个新 segment 的数据部分的长度，来分配一块空间
					seg->conv = conv;
					seg->cmd = cmd;
					seg->frg = frg;
					seg->wnd = wnd;
					seg->ts = ts;
					seg->sn = sn;
					seg->una = una;
					seg->len = len;

					if (len > 0) {
						memcpy(seg->data, data, len);
					}

					ikcp_parse_data(kcp, seg); // 构建了这个新的 segment 的 struct 对象之后，尝试将其插入接收缓存之中
				}
			}
		}
		else if (cmd == IKCP_CMD_WASK) { // 接收到询问窗口类型的 segment，本端应发回给对方一个告知窗口的 segment
			// ready to send back IKCP_CMD_WINS in ikcp_flush
			// tell remote my window size
			kcp->probe |= IKCP_ASK_TELL; // 将探查控制变量 kcp->probe 的 IKCP_ASK_TELL 位置 1，表示要告知对方（远端）我的接收队列的剩余容量的情况
			if (ikcp_canlog(kcp, IKCP_LOG_IN_PROBE)) {
				ikcp_log(kcp, IKCP_LOG_IN_PROBE, "input probe");
			}
		}
		else if (cmd == IKCP_CMD_WINS) { // 接收到告知窗口类型的 segment
			// do nothing
			// 对方告知我方，它的（剩余）接收窗口的大小，由于在上面已经有了对我方的 kcp->rmt_wnd := wnd 的设置，因此不需要再做一遍了
			// 因此可以看出，其实每一个 segment 的 wnd 字段都具有告知窗口的效果，无论你是否将其设置为告知窗口类型
			if (ikcp_canlog(kcp, IKCP_LOG_IN_WINS)) {
				ikcp_log(kcp, IKCP_LOG_IN_WINS,
					"input wins: %lu", (unsigned long)(wnd));
			}
		}
		else {
			return -3;
		}

		data += len; // data 指针后移
		size -= len; // 计算剩余的字节数
	}

	if (flag != 0) {
		ikcp_parse_fastack(kcp, maxack, latest_ts);
	}

	if (_itimediff(kcp->snd_una, prev_una) > 0) { // kcp->snd_una 更新了，说明本端收到了若干确认，发送窗口的左沿向右移动了
		// 更新拥塞窗口 ###################### TODO ######################
		if (kcp->cwnd < kcp->rmt_wnd) {
			IUINT32 mss = kcp->mss;
			if (kcp->cwnd < kcp->ssthresh) {
				kcp->cwnd++;
				kcp->incr += mss;
			}	else {
				if (kcp->incr < mss) kcp->incr = mss;
				kcp->incr += (mss * mss) / kcp->incr + (mss / 16);
				if ((kcp->cwnd + 1) * mss <= kcp->incr) {
				#if 1
					kcp->cwnd = (kcp->incr + mss - 1) / ((mss > 0)? mss : 1);
				#else
					kcp->cwnd++;
				#endif
				}
			}
			if (kcp->cwnd > kcp->rmt_wnd) {
				kcp->cwnd = kcp->rmt_wnd;
				kcp->incr = kcp->rmt_wnd * mss;
			}
		}
	}

	return 0;
}


//---------------------------------------------------------------------
// ikcp_encode_seg
// 将 segment 编码成字节流，写入到 ptr 中
//---------------------------------------------------------------------
static char *ikcp_encode_seg(char *ptr, const IKCPSEG *seg)
{
	ptr = ikcp_encode32u(ptr, seg->conv);
	ptr = ikcp_encode8u(ptr, (IUINT8)seg->cmd);
	ptr = ikcp_encode8u(ptr, (IUINT8)seg->frg);
	ptr = ikcp_encode16u(ptr, (IUINT16)seg->wnd);
	ptr = ikcp_encode32u(ptr, seg->ts);
	ptr = ikcp_encode32u(ptr, seg->sn);
	ptr = ikcp_encode32u(ptr, seg->una);
	ptr = ikcp_encode32u(ptr, seg->len);
	return ptr;
}

/** 
 * 根据 kcp->rcv_wnd 所给出的接收队列的节点数上限，
 * 以及目前接收队列中的节点数 kcp->nrcv_que（接收队列中一个节点对应于一个 segment），
 * 计算出目前接收队列的剩余容量，注意剩余容量最小为 0（即不会返回小于零的值）。
 */
static int ikcp_wnd_unused(const ikcpcb *kcp)
{
	if (kcp->nrcv_que < kcp->rcv_wnd) {
		return kcp->rcv_wnd - kcp->nrcv_que;
	}
	return 0;
}


//---------------------------------------------------------------------
// ikcp_flush
//---------------------------------------------------------------------
void ikcp_flush(ikcpcb *kcp)
{
	IUINT32 current = kcp->current;
	char *buffer = kcp->buffer; // 一个 buffer，用以暂存马上要发送出去的 segment 的字节流
	char *ptr = buffer; // 一个在 buffer 上移动的指针，便于将多个 segment 的字节流在 buffer 中连接起来
	int count, size, i;
	IUINT32 resent, cwnd;
	IUINT32 rtomin;
	struct IQUEUEHEAD *p;
	int change = 0;
	int lost = 0;
	IKCPSEG seg;

	// 'ikcp_update' haven't been called. 
	if (kcp->updated == 0) return; // 如果 ikcp_update 函数还没被调用过，也就是 kcp->updated 标记表明 kcp 还没被更新过，则不应该调用本函数

	seg.conv = kcp->conv; // conv 字段用于标识当前这个会话
	seg.cmd = IKCP_CMD_ACK; // 将 segment 初始设置为 ACK 类型，是因为下面马上就要将 acklist 里的 ack 都发送出去了
	seg.frg = 0; // 每个 ACK 类型的 segment 都自成一条消息（即一条消息只拆分成一个 fragment）
	seg.wnd = ikcp_wnd_unused(kcp); // wnd 字段记录了目前本端的接收队列的剩余容量
	seg.una = kcp->rcv_nxt; // una 字段提供累计确认，本端的 rcv_nxt 是目前接收队列所期待的下一个 segment 的序号，因此表示本端确认收到了所有序号小于 rcv_nxt 的 segment
	seg.len = 0; // ACK 类型的 segment 不携带数据
	seg.sn = 0;
	seg.ts = 0;

	// flush acknowledges
	// 将 acklist 中的 ack 转变为 ACK 类型的 segment，编码成字节流，拼接起来发送
	count = kcp->ackcount;
	for (i = 0; i < count; i++) {
		size = (int)(ptr - buffer);
		if (size + (int)IKCP_OVERHEAD > (int)kcp->mtu) { // 当 buffer 中的字节流达到了一个 kcp->mtu 长度，就发送出去
			ikcp_output(kcp, buffer, size);
			ptr = buffer; // 发送完后将 ptr 指针重置到 buffer 的起始位置
		}
		ikcp_ack_get(kcp, i, &seg.sn, &seg.ts); // 获取 kcp->acklist 中的第 i 个 ack，分别写入到 seg 的 sn 和 ts 字段
		ptr = ikcp_encode_seg(ptr, &seg); // 将 seg 编码成字节流，传入 in_ptr，返回 out_ptr，字节流记录在 buffer 的 [in_ptr, out_ptr) 区间内
	}

	kcp->ackcount = 0; // 本端的 kcp->acklist 已经被全部发送走了，计数器清零

	// probe window size (if remote window size equals zero)
	// 当本端所记录下的对方的（剩余）接收窗口 kcp->rmt_wnd 为零，需要考虑向对方询问窗口
	// kcp->probe_wait 表示询问窗口需要等待的时间，kcp->ts_probe 表示下次询问窗口的时间戳，两者都置为零时意思是目前本端的“询问窗口状态”是关闭的
	if (kcp->rmt_wnd == 0) {
		if (kcp->probe_wait == 0) { // 如果此前本端的“询问窗口状态”是关闭的
			kcp->probe_wait = IKCP_PROBE_INIT; // 初始化 kcp->probe_wait
			kcp->ts_probe = kcp->current + kcp->probe_wait; // 初始化 kcp->ts_probe 时间戳
			// 打开并进入“询问窗口状态”
		}	
		else { // 此前本端就已经处在“询问窗口状态”
			// 如果还没到下次询问窗口的时间点，那么就什么事都不会发生
			if (_itimediff(kcp->current, kcp->ts_probe) >= 0) { // 如果已经到了要询问窗口的时间点

				// 下面这段代码是对 kcp->probe_wait 的处理，询问窗口需要等待的时间变长了
				if (kcp->probe_wait < IKCP_PROBE_INIT) 
					kcp->probe_wait = IKCP_PROBE_INIT;
				kcp->probe_wait += kcp->probe_wait / 2; // 等待时间变为原来的 1.5 倍
				if (kcp->probe_wait > IKCP_PROBE_LIMIT)
					kcp->probe_wait = IKCP_PROBE_LIMIT; // 但不能超过上限 IKCP_PROBE_LIMIT
				
				kcp->ts_probe = kcp->current + kcp->probe_wait; // 根据 kcp->probe_wait 计算下一次询问窗口的时间点

				kcp->probe |= IKCP_ASK_SEND; // 触发了本次询问，将 kcp->probe 的 IKCP_ASK_SEND 位置 1，即表示要向对方询问窗口
			}
		}
	}	else { // 如果远端的（剩余）接收窗口不为零，则关闭“询问窗口状态”
		kcp->ts_probe = 0;
		kcp->probe_wait = 0;
	}

	// flush window probing commands
	if (kcp->probe & IKCP_ASK_SEND) { // 如果发现 kcp->probe 的 IKCP_ASK_SEND 位为 1，表明需要向对方发送询问窗口的 segment
		seg.cmd = IKCP_CMD_WASK; // 将 segment 的类型标记为询问窗口类型
		size = (int)(ptr - buffer);
		if (size + (int)IKCP_OVERHEAD > (int)kcp->mtu) { // 当 buffer 中的字节流达到了一个 kcp->mtu 长度，就发送出去
			ikcp_output(kcp, buffer, size);
			ptr = buffer; // 发送完后将 ptr 指针重置到 buffer 的起始位置
		}
		ptr = ikcp_encode_seg(ptr, &seg); // 将 segment 编码成字节流，填入到 buffer 中
	}

	// flush window probing commands
	if (kcp->probe & IKCP_ASK_TELL) { // 如果发现 kcp->probe 的 IKCP_ASK_TELL 位为 1，表明需要向对方发送告知窗口的 segment
		seg.cmd = IKCP_CMD_WINS; // 将 segment 的类型标记为告知窗口类型
		size = (int)(ptr - buffer);
		if (size + (int)IKCP_OVERHEAD > (int)kcp->mtu) { // 当 buffer 中的字节流达到了一个 kcp->mtu 长度，就发送出去
			ikcp_output(kcp, buffer, size);
			ptr = buffer;
		}
		ptr = ikcp_encode_seg(ptr, &seg); // 将 segment 编码成字节流，填入到 buffer 中
	}

	kcp->probe = 0; // 将 kcp->probe 的 IKCP_ASK_TELL 位和 IKCP_ASK_SEND 位都重置为 0

	// calculate window size，根据发送窗口上限 kcp->snd_wnd、远端剩余接收窗口 kcp->rmt_wnd 以及拥塞窗口 kcp->cwnd 计算最终的实际发送窗口 cwnd
	cwnd = _imin_(kcp->snd_wnd, kcp->rmt_wnd); // cwnd 是实际发送窗口，它不能超过设定好的发送窗口上限 kcp->snd_wnd，也不能超过远端的（剩余）接收窗口 kcp->rmt_wnd
	if (kcp->nocwnd == 0) cwnd = _imin_(kcp->cwnd, cwnd); // kcp->nocwnd 表示关闭拥塞控制，因此如果开启拥塞控制的话，那么实际发送窗口 cwnd 还不能超过拥塞窗口 kcp->cwnd

	// move data from snd_queue to snd_buf
	// 将发送队列中的 segment 转移到发送缓存中
	while (_itimediff(kcp->snd_nxt, kcp->snd_una + cwnd) < 0) { // 根据实际发送窗口，确认是否还能往发送缓存中转移 segment
		IKCPSEG *newseg;
		if (iqueue_is_empty(&kcp->snd_queue)) break;

		newseg = iqueue_entry(kcp->snd_queue.next, IKCPSEG, node); // 获取发送队列的队头节点，即发送队列的首个 segment

		iqueue_del(&newseg->node); // 从发送队列中将该 segment 节点拆下
		iqueue_add_tail(&newseg->node, &kcp->snd_buf); // 然后添加到发送缓存的末尾
		kcp->nsnd_que--;
		kcp->nsnd_buf++;

		// 给该 segment 首部的字段赋值
		newseg->conv = kcp->conv; // 会话的编号
		newseg->cmd = IKCP_CMD_PUSH; // 将该 segment 设定为数据类型
		newseg->wnd = seg.wnd; // wnd 字段记录下本端的接收队列的剩余容量（即剩余接收窗口大小）
		newseg->ts = current; // 发送数据类型的 segment，其时间戳字段记录的就是该 segment 发送的时间点
		newseg->sn = kcp->snd_nxt++; // 区间 [kcp->snd_una, kcp->snd_nxt) 标明了当前发送缓存对应的序号范围
		newseg->una = kcp->rcv_nxt; // una 字段用以累计确认，本端向远端确认，已经接收到所有序号小于 kcp->rcv_nxt 的 segment
		// 以下这些成员，不属于 KCP segment 的首部字段
		newseg->resendts = current;
		newseg->rto = kcp->rx_rto;
		newseg->fastack = 0;
		newseg->xmit = 0;
	}

	// calculate resent
	resent = (kcp->fastresend > 0)? (IUINT32)kcp->fastresend : 0xffffffff;
	rtomin = (kcp->nodelay == 0)? (kcp->rx_rto >> 3) : 0;

	// flush data segments
	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = p->next) { // 从头到尾遍历发送缓存
		IKCPSEG *segment = iqueue_entry(p, IKCPSEG, node); // 根据当前节点获取 segment
		int needsend = 0;
		if (segment->xmit == 0) {
			needsend = 1;
			segment->xmit++;
			segment->rto = kcp->rx_rto;
			segment->resendts = current + segment->rto + rtomin;
		}
		else if (_itimediff(current, segment->resendts) >= 0) {
			needsend = 1;
			segment->xmit++;
			kcp->xmit++;
			if (kcp->nodelay == 0) {
				segment->rto += _imax_(segment->rto, (IUINT32)kcp->rx_rto);
			}	else {
				IINT32 step = (kcp->nodelay < 2)? 
					((IINT32)(segment->rto)) : kcp->rx_rto;
				segment->rto += step / 2;
			}
			segment->resendts = current + segment->rto;
			lost = 1;
		}
		else if (segment->fastack >= resent) {
			if ((int)segment->xmit <= kcp->fastlimit || 
				kcp->fastlimit <= 0) {
				needsend = 1;
				segment->xmit++;
				segment->fastack = 0;
				segment->resendts = current + segment->rto;
				change++;
			}
		}

		if (needsend) {
			int need;
			segment->ts = current;
			segment->wnd = seg.wnd;
			segment->una = kcp->rcv_nxt;

			size = (int)(ptr - buffer);
			need = IKCP_OVERHEAD + segment->len;

			if (size + need > (int)kcp->mtu) {
				ikcp_output(kcp, buffer, size);
				ptr = buffer;
			}

			ptr = ikcp_encode_seg(ptr, segment);

			if (segment->len > 0) {
				memcpy(ptr, segment->data, segment->len);
				ptr += segment->len;
			}

			if (segment->xmit >= kcp->dead_link) {
				kcp->state = (IUINT32)-1;
			}
		}
	}

	// flush remain segments
	size = (int)(ptr - buffer);
	if (size > 0) {
		ikcp_output(kcp, buffer, size);
	}

	// update ssthresh
	if (change) {
		IUINT32 inflight = kcp->snd_nxt - kcp->snd_una;
		kcp->ssthresh = inflight / 2;
		if (kcp->ssthresh < IKCP_THRESH_MIN)
			kcp->ssthresh = IKCP_THRESH_MIN;
		kcp->cwnd = kcp->ssthresh + resent;
		kcp->incr = kcp->cwnd * kcp->mss;
	}

	if (lost) {
		kcp->ssthresh = cwnd / 2;
		if (kcp->ssthresh < IKCP_THRESH_MIN)
			kcp->ssthresh = IKCP_THRESH_MIN;
		kcp->cwnd = 1;
		kcp->incr = kcp->mss;
	}

	if (kcp->cwnd < 1) {
		kcp->cwnd = 1;
		kcp->incr = kcp->mss;
	}
}


//---------------------------------------------------------------------
// update state (call it repeatedly, every 10ms-100ms), or you can ask 
// ikcp_check when to call it again (without ikcp_input/_send calling).
// 'current' - current timestamp in millisec. 
//---------------------------------------------------------------------
void ikcp_update(ikcpcb *kcp, IUINT32 current)
{
	IINT32 slap;

	kcp->current = current; // 更新当前时间

	// kcp->updated 用来标记 kcp 是否有被 update 过
	// kcp->ts_flush 是下次 flush 的时间戳
	// 如果 kcp 是第一次被 ikcp_update 函数 update，那么下次 flush 的时间点就是现在
	if (kcp->updated == 0) {
		kcp->updated = 1;
		kcp->ts_flush = kcp->current;
	}

	// 如果 kcp 之前就被更新过了，就要根据当前时间 kcp->current 和下次 flush 的时间 kcp->ts_flush 来判断是否要 flush
	slap = _itimediff(kcp->current, kcp->ts_flush);

	// 这个应该是针对出现 kcp->current 和 kcp->ts_flush 差值过大的情况做的修补，如果差值过大则直接现在就 flush
	if (slap >= 10000 || slap < -10000) {
		kcp->ts_flush = kcp->current;
		slap = 0;
	}

	// 如果当前时间 kcp->current 已经越过了 kcp->ts_flush 这个时间戳，说明需要立刻 flush
	if (slap >= 0) {
		kcp->ts_flush += kcp->interval; // kcp->interval 是内部设定的 flush 刷新时间间隔
		if (_itimediff(kcp->current, kcp->ts_flush) >= 0) { // 如果加上一个“间隔”后依然还是没到 kcp->current 时间点，那么干脆重新设置
			kcp->ts_flush = kcp->current + kcp->interval;
		}
		ikcp_flush(kcp);
	}
}


//---------------------------------------------------------------------
// Determine when should you invoke ikcp_update:
// returns when you should invoke ikcp_update in millisec, if there 
// is no ikcp_input/_send calling. you can call ikcp_update in that
// time, instead of call update repeatly.
// Important to reduce unnacessary ikcp_update invoking. use it to 
// schedule ikcp_update (eg. implementing an epoll-like mechanism, 
// or optimize ikcp_update when handling massive kcp connections)
//---------------------------------------------------------------------
IUINT32 ikcp_check(const ikcpcb *kcp, IUINT32 current)
{
	IUINT32 ts_flush = kcp->ts_flush;
	IINT32 tm_flush = 0x7fffffff;
	IINT32 tm_packet = 0x7fffffff;
	IUINT32 minimal = 0;
	struct IQUEUEHEAD *p;

	if (kcp->updated == 0) {
		return current;
	}

	if (_itimediff(current, ts_flush) >= 10000 ||
		_itimediff(current, ts_flush) < -10000) {
		ts_flush = current;
	}

	if (_itimediff(current, ts_flush) >= 0) {
		return current;
	}

	tm_flush = _itimediff(ts_flush, current);

	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = p->next) {
		const IKCPSEG *seg = iqueue_entry(p, const IKCPSEG, node);
		IINT32 diff = _itimediff(seg->resendts, current);
		if (diff <= 0) {
			return current;
		}
		if (diff < tm_packet) tm_packet = diff;
	}

	minimal = (IUINT32)(tm_packet < tm_flush ? tm_packet : tm_flush);
	if (minimal >= kcp->interval) minimal = kcp->interval;

	return current + minimal;
}


/**
 * 手动设置 KCP 协议的 MTU，注意会导致 kcp->buffer 空间的重新分配
 */
int ikcp_setmtu(ikcpcb *kcp, int mtu)
{
	char *buffer;
	if (mtu < 50 || mtu < (int)IKCP_OVERHEAD) // 设置的 MTU 不能过小
		return -1;
	buffer = (char*)ikcp_malloc((mtu + IKCP_OVERHEAD) * 3);
	if (buffer == NULL) 
		return -2;
	kcp->mtu = mtu;
	kcp->mss = kcp->mtu - IKCP_OVERHEAD;
	ikcp_free(kcp->buffer);
	kcp->buffer = buffer;
	return 0;
}

/**
 * 手动设置 KCP 的 flush 刷新时间间隔（即 kcp->interval）
 * 设置该间隔的上下限是 5000 和 10
 */
int ikcp_interval(ikcpcb *kcp, int interval)
{
	if (interval > 5000) interval = 5000;
	else if (interval < 10) interval = 10;
	kcp->interval = interval;
	return 0;
}

int ikcp_nodelay(ikcpcb *kcp, int nodelay, int interval, int resend, int nc)
{
	if (nodelay >= 0) {
		kcp->nodelay = nodelay;
		if (nodelay) {
			kcp->rx_minrto = IKCP_RTO_NDL;	
		}	
		else {
			kcp->rx_minrto = IKCP_RTO_MIN;
		}
	}
	if (interval >= 0) {
		if (interval > 5000) interval = 5000;
		else if (interval < 10) interval = 10;
		kcp->interval = interval;
	}
	if (resend >= 0) {
		kcp->fastresend = resend;
	}
	if (nc >= 0) {
		kcp->nocwnd = nc;
	}
	return 0;
}

/**
 * 自主设定 KCP 的发送窗口大小 kcp->snd_wnd 和接收窗口大小 kcp->rcv_wnd
 * 注意 kcp->snd_wnd 实际上是对实际发送窗口给定一个上限，因为实际的发送窗口大小还会进一步受到其他约束（例如拥塞窗口）
 * 注意 kcp->rcv_wnd 是本端接收队列的节点数的最大值，本端的接收队列的容量直接受该值的控制，但你不能将其设定成小于 IKCP_WND_RCV 的值
 */
int ikcp_wndsize(ikcpcb *kcp, int sndwnd, int rcvwnd)
{
	if (kcp) {
		if (sndwnd > 0) {
			kcp->snd_wnd = sndwnd;
		}
		if (rcvwnd > 0) {   // must >= max fragment size
			kcp->rcv_wnd = _imax_(rcvwnd, IKCP_WND_RCV);
		}
	}
	return 0;
}

int ikcp_waitsnd(const ikcpcb *kcp)
{
	return kcp->nsnd_buf + kcp->nsnd_que;
}


// read conv
IUINT32 ikcp_getconv(const void *ptr)
{
	IUINT32 conv;
	ikcp_decode32u((const char*)ptr, &conv);
	return conv;
}


