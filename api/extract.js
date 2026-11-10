const L=require('../server.js'),O=process.env.ALLOW_ORIGIN||'*';
module.exports=async(req,res)=>{res.setHeader('Access-Control-Allow-Origin',O);res.setHeader('Access-Control-Allow-Headers','Content-Type');res.setHeader('Access-Control-Allow-Methods','POST,OPTIONS');
if(req.method==='OPTIONS')return res.status(204).end();
if(req.method!=='POST')return res.status(405).json({ok:false,code:'METHOD',message:'Use POST'});
try{let b=req.body;if(typeof b==='string')b=JSON.parse(b||'{}');const url=b&&b.url;if(typeof url!=='string'||url.length>2048)return res.status(200).json({ok:false,code:'BAD_URL',message:'Missing or invalid URL.'});res.status(200).json(await L.extract(url.trim()))}
catch(e){res.status(200).json({ok:false,code:e.code||'ERROR',message:e.code?e.message:'Extraction failed unexpectedly.'})}};
