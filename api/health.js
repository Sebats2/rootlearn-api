module.exports=(req,res)=>{res.setHeader('Access-Control-Allow-Origin',process.env.ALLOW_ORIGIN||'*');res.status(200).json({ok:true})};
