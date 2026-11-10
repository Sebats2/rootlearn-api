#!/usr/bin/env node
/* Root Learn extraction service. Node 18+, zero dependencies.
   Run: node server.js   (PORT=8787, ALLOW_ORIGIN=* by default; set ALLOW_ORIGIN to your app origin in production)
   POST /extract {url} -> {ok,type,title,author,source,text,...} | {ok:false,code,message} ; GET /health */
const http=require('http'),https=require('https'),dns=require('dns').promises,net=require('net');
const PORT=+process.env.PORT||8787,ORIGIN=process.env.ALLOW_ORIGIN||'*',PRIV=process.env.ALLOW_PRIVATE==='1',MAX=3e6,TMO=12e3,CAP=6e4;
class E extends Error{constructor(code,msg){super(msg);this.code=code}}
const priv=ip=>{if(net.isIPv4(ip)){const[a,b]=ip.split('.').map(Number);return a==0||a==10||a==127||(a==100&&b>=64&&b<128)||(a==169&&b==254)||(a==172&&b>=16&&b<32)||(a==192&&b==168)||(a==192&&b==0)||(a==198&&(b==18||b==19))||a>=224}
const x=ip.toLowerCase();if(x.startsWith('::ffff:')){const r=x.slice(7);return r.includes(':')?true:priv(r)}return x=='::1'||x=='::'||/^f[cd]/.test(x)||/^fe[89ab]/.test(x)||x.startsWith('ff')};
async function chk(u){let p;try{p=new URL(u)}catch{throw new E('BAD_URL','That is not a valid URL.')}
if(!/^https?:$/.test(p.protocol))throw new E('BAD_URL','Only http and https links are supported.');
if(p.username||p.password)throw new E('BAD_URL','URLs with embedded credentials are not allowed.');
if(!PRIV&&p.port&&!['80','443'].includes(p.port))throw new E('BLOCKED','Non-standard ports are not allowed.');
const host=p.hostname.replace(/^\[|\]$/g,'');
const ad=net.isIP(host)?[{address:host,family:net.isIP(host)}]:await dns.lookup(host,{all:true}).catch(()=>{throw new E('DNS','Could not resolve that website.')});
if(!PRIV&&ad.some(a=>priv(a.address)))throw new E('BLOCKED','That address is not allowed (private or internal network).');
return{p,ip:ad[0]}}
/* every hop is re-validated; the validated IP is pinned so DNS rebinding cannot swap it */
async function get(u,hdr={},hops=0){const{p,ip}=await chk(u);return new Promise((ok,no)=>{const m=p.protocol=='https:'?https:http,h=p.hostname.replace(/^\[|\]$/g,'');
const rq=m.request({host:h,port:p.port||undefined,path:p.pathname+p.search,method:'GET',servername:net.isIP(h)?undefined:h,lookup:(x,o,cb)=>o&&o.all?cb(null,[{address:ip.address,family:ip.family}]):cb(null,ip.address,ip.family),timeout:TMO,
headers:{'User-Agent':'RootLearnBot/1.0 (study notes; honors access controls)','Accept':'text/html,text/plain;q=0.9,*/*;q=0.4','Accept-Language':'en',...hdr}},res=>{const s=res.statusCode;
if([301,302,303,307,308].includes(s)&&res.headers.location){res.resume();if(hops>=4)return no(new E('REDIRECTS','Too many redirects.'));return get(new URL(res.headers.location,u).href,hdr,hops+1).then(ok,no)}
if([401,402,403,407,451].includes(s)){res.resume();return no(new E('ACCESS','This page needs a login, a subscription, or blocks automated access. Root Learn does not bypass access controls.'))}
if(s==404||s==410){res.resume();return no(new E('NOT_FOUND','The page was not found (HTTP '+s+').'))}
if(s>=400){res.resume();return no(new E('HTTP','The website returned an error (HTTP '+s+').'))}
const ch=[];let n=0;res.on('data',d=>{n+=d.length;if(n>MAX){rq.destroy(new E('TOO_BIG','The page is too large to import.'))}else ch.push(d)});
res.on('end',()=>{const ct=String(res.headers['content-type']||'').toLowerCase(),cs=(ct.match(/charset=([\w-]+)/)||[])[1]||'utf-8';let body;try{body=new TextDecoder(cs).decode(Buffer.concat(ch))}catch{body=Buffer.concat(ch).toString('utf8')}ok({ct,body,url:u})});res.on('error',no)});
rq.on('timeout',()=>rq.destroy(new E('TIMEOUT','The website took too long to respond.')));rq.on('error',e=>no(e instanceof E?e:new E('NETWORK','Could not reach the website: '+e.message)));rq.end()})}
const ent=s=>s.replace(/&(#x?[0-9a-f]+|amp|lt|gt|quot|apos|nbsp|mdash|ndash|hellip|rsquo|lsquo|rdquo|ldquo);/gi,(m,k)=>{const t={amp:'&',lt:'<',gt:'>',quot:'"',apos:"'",nbsp:' ',mdash:'—',ndash:'–',hellip:'…',rsquo:'’',lsquo:'‘',rdquo:'”',ldquo:'“'};k=k.toLowerCase();if(t[k])return t[k];const c=k[1]=='x'?parseInt(k.slice(2),16):parseInt(k.slice(1),10);return c>0&&c<1114112?String.fromCodePoint(c):m});
const meta=(h,n)=>{const m=h.match(new RegExp(`<meta[^>]+(?:property|name)=["']${n}["'][^>]*>`,'i')),c=m&&m[0].match(/content=["']([^"']*)["']/i);return c?ent(c[1]).trim():''};
const JUNK=/(cookie|subscribe|newsletter|advertisement|sponsored|all rights reserved|share on|follow us|sign up|log in|privacy policy|read more|related articles|click here)/i;
function article(html,url){const h=html.replace(/<!--[\s\S]*?-->/g,'').replace(/<(script|style|noscript|svg|iframe|form|template|nav|footer|aside|header|button|select)\b[\s\S]*?<\/\1>/gi,'');
const tx=s=>ent(s.replace(/<[^>]+>/g,' ')).replace(/\s+/g,' ').trim(),c=[];for(const re of[/<article\b[\s\S]*?<\/article>/gi,/<main\b[\s\S]*?<\/main>/gi,/<div[^>]+role=["']main["'][\s\S]*?<\/div>/gi,/<body\b[\s\S]*<\/body>/gi]){for(const m of h.matchAll(re))c.push(m[0]);if(c.length&&re.source.startsWith('<article'))break}
const box=c.sort((a,b)=>tx(b).length-tx(a).length)[0]||h,out=[];let last='';
for(const m of box.matchAll(/<(h[1-4]|p|li|blockquote|pre)\b[^>]*>([\s\S]*?)<\/\1>/gi)){const k=m[1].toLowerCase(),t=tx(m[2]);if(!t||t==last)continue;
if(k[0]=='h'){if(t.length<140&&!JUNK.test(t))out.push('\n'+'#'.repeat(+k[1]==1?1:+k[1])+' '+t)}else if(t.length>=(k=='li'?25:45)&&!(JUNK.test(t)&&t.length<160)){out.push(t)}last=t}
const text=out.join('\n').trim();if(text.replace(/[#\s]/g,'').length<200)throw new E('EMPTY','No readable article text was found. The page may need JavaScript to display, or may be behind a paywall.');
const host=new URL(url).hostname.replace(/^www\./,''),title=meta(h,'og:title')||(h.match(/<title[^>]*>([\s\S]*?)<\/title>/i)||[])[1]&&tx(h.match(/<title[^>]*>([\s\S]*?)<\/title>/i)[1])||host,
type=/(^|\.)(medium\.com|substack\.com|wordpress\.com|blogspot\.com|dev\.to|hashnode\.dev)$/.test(host)||/blog/.test(url)?'blog':/(khanacademy|coursera|edx|wikipedia|britannica|openstax|ck12|brilliant)\./.test(host)||/\.edu$/.test(host)?'learning':/<article\b/i.test(html)||/og:type["'][^>]*article/i.test(html)?'article':'webpage';
return{type,title,author:meta(h,'author')||meta(h,'article:author'),source:meta(h,'og:site_name')||host,published:meta(h,'article:published_time'),text}}
const ytId=p=>{const h=p.hostname.replace(/^www\.|^m\./,'');if(h=='youtu.be')return p.pathname.slice(1).split('/')[0]||null;if(h=='youtube.com'||h=='music.youtube.com'){if(p.pathname=='/watch')return p.searchParams.get('v');const m=p.pathname.match(/^\/(shorts|embed|live)\/([\w-]{11})/);return m&&m[2]}return null};
function ytParse(html){const i=html.indexOf('ytInitialPlayerResponse');if(i<0)throw new E('YT_PARSE','Could not read this video page (YouTube may have shown a consent or bot-check page).');
const s=html.indexOf('{',i);let d=0,j=s,q=false,x=false;for(;j<html.length;j++){const c=html[j];if(q){if(x)x=false;else if(c=='\\')x=true;else if(c=='"')q=false}else if(c=='"')q=true;else if(c=='{')d++;else if(c=='}'&&--d==0)break}
const r=JSON.parse(html.slice(s,j+1)),v=r.videoDetails||{},t=((((r.captions||{}).playerCaptionsTracklistRenderer)||{}).captionTracks)||[];
return{title:v.title||'',author:v.author||'',tracks:t.map(x=>({url:x.baseUrl,lang:x.languageCode,auto:x.kind=='asr'}))}}
const ytSegs=j=>{const o=[];for(const e of j.events||[]){if(!e.segs)continue;const t=e.segs.map(s=>s.utf8).join('').replace(/\s+/g,' ').trim();if(t)o.push({t:Math.floor((e.tStartMs||0)/1e3),x:t})}return o};
const ts=n=>{const h=Math.floor(n/3600),m=Math.floor(n%3600/60),s=n%60;return(h?h+':'+String(m).padStart(2,'0'):m)+':'+String(s).padStart(2,'0')};
const ytText=g=>{const o=[];let w=null;for(const s of g){if(!w||s.t-w.t>=45){w={t:s.t,x:[]};o.push(w)}w.x.push(s.x)}return o.map(w=>`[${ts(w.t)}] ${w.x.join(' ')}`).join('\n')};
async function youtube(p,id){if(!/^[\w-]{11}$/.test(id||''))throw new E('BAD_URL','That YouTube link has no valid video ID.');
const pg=await get(`https://www.youtube.com/watch?v=${id}&hl=en`,{Cookie:'CONSENT=YES+1; SOCS=CAI'}),info=ytParse(pg.body);
if(!info.tracks.length)return{ok:false,code:'NO_TRANSCRIPT',title:info.title,author:info.author,message:'This video has no captions or transcript available, so Root Learn cannot create notes from it. Only the title was retrieved; the video was not processed.'};
const want=p.searchParams.get('lang')||'en',t=info.tracks.find(x=>x.lang==want&&!x.auto)||info.tracks.find(x=>x.lang.startsWith(want)&&!x.auto)||info.tracks.find(x=>x.lang.startsWith(want))||info.tracks[0];
const cu=new URL(t.url);if(!/(^|\.)youtube\.com$/.test(cu.hostname))throw new E('YT_PARSE','Unexpected caption address.');cu.searchParams.set('fmt','json3');
const cr=await get(cu.href,{Cookie:'CONSENT=YES+1; SOCS=CAI'});let segs=[];try{segs=ytSegs(JSON.parse(cr.body))}catch{}
if(!segs.length)return{ok:false,code:'TRANSCRIPT_EMPTY',title:info.title,author:info.author,message:'Captions exist but YouTube did not return their text to the server. Only the title was retrieved; the video was not processed. Try again later.'};
return{ok:true,type:'youtube',title:info.title,author:info.author,source:'YouTube',lang:t.lang,auto:t.auto,text:ytText(segs),videoId:id}}
async function extract(u){const{p}=await chk(u),id=ytId(p);let r;
if(id!==null&&/(^|\.)(youtube\.com|youtu\.be)$/.test(p.hostname)){r=await youtube(p,id);if(!r.ok)return r}
else{const g=await get(p.href);if(/pdf|octet-stream|msword|officedocument/.test(g.ct)||/\.(pdf|docx?|pptx?)$/i.test(p.pathname))throw new E('UNSUPPORTED','Document files are not supported by link. Download the PDF and use PDF Lab instead.');
if(/text\/(plain|markdown)/.test(g.ct)||/\.(txt|md)$/i.test(p.pathname)){const t=g.body.trim();if(t.length<100)throw new E('EMPTY','The text document is empty.');r={ok:true,type:'document',title:decodeURIComponent(p.pathname.split('/').pop()||p.hostname),author:'',source:p.hostname,text:t}}
else if(/html|xml/.test(g.ct)||!g.ct)r={ok:true,...article(g.body,g.url)};else throw new E('UNSUPPORTED','This content type ('+(g.ct.split(';')[0]||'unknown')+') is not supported.')}
r.truncated=r.text.length>CAP;r.text=r.text.slice(0,CAP);r.url=p.href;return r}
const rs=(res,c,o)=>{res.writeHead(c,{'Content-Type':'application/json','Access-Control-Allow-Origin':ORIGIN,'Access-Control-Allow-Headers':'Content-Type','Access-Control-Allow-Methods':'GET,POST,OPTIONS'});res.end(JSON.stringify(o))};
module.exports={priv,chk,article,ytParse,ytSegs,ytText,ytId,extract,get};
if(require.main===module)http.createServer((q,res)=>{if(q.method=='OPTIONS')return rs(res,204,{});if(q.url=='/health')return rs(res,200,{ok:true});
if(q.method!='POST'||q.url!='/extract')return rs(res,404,{ok:false,code:'NOT_FOUND',message:'Unknown endpoint'});let b='';q.on('data',d=>{b+=d;if(b.length>4096)q.destroy()});
q.on('end',async()=>{try{const{url}=JSON.parse(b||'{}');if(typeof url!='string')throw new E('BAD_URL','Missing URL.');rs(res,200,await extract(url.trim()))}catch(e){rs(res,e.code?200:500,{ok:false,code:e.code||'ERROR',message:e.code?e.message:'Extraction failed unexpectedly.'})}})}).listen(PORT,()=>console.log('Root Learn extraction service on :'+PORT));
