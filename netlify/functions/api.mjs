import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const store = getStore("tavis-store");
const json = (data, status=200) => new Response(JSON.stringify(data), {status, headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store","access-control-allow-origin":"*"}});
const read = async key => (await store.get(key,{type:"json"})) || null;
const write = async (key,value) => store.setJSON(key,value);
const env = key => Netlify.env.get(key);
const secret = () => env("TOKEN_SECRET") || env("ADMIN_PASSWORD") || "";
const sign = payload => { const body=Buffer.from(JSON.stringify(payload)).toString("base64url"); const sig=crypto.createHmac("sha256",secret()).update(body).digest("base64url"); return `${body}.${sig}`; };
const verify = token => { try { const [body,sig]=token.split("."); const expected=crypto.createHmac("sha256",secret()).update(body).digest(); const actual=Buffer.from(sig,"base64url"); if(actual.length!==expected.length||!crypto.timingSafeEqual(actual,expected))return false; const p=JSON.parse(Buffer.from(body,"base64url").toString()); return p.exp>Date.now(); } catch { return false; } };
const id = () => crypto.randomUUID();
export default async (req, context) => {
  if(req.method==="OPTIONS") return new Response(null,{status:204,headers:{"access-control-allow-origin":"*","access-control-allow-methods":"GET,POST,PUT,DELETE,OPTIONS","access-control-allow-headers":"Content-Type,Authorization"}});
  const pathname=new URL(req.url).pathname;
  const routedPath=pathname.includes("/.netlify/functions/api")
    ? pathname.split("/.netlify/functions/api")[1]
    : pathname.replace(/^\/api\/?/,"");
  const path=routedPath.split("/").filter(Boolean);
  const [resource,resourceId]=path;
  try {
    if(resource==="login"&&req.method==="POST"){
      const {password}=await req.json();
      const configured=env("ADMIN_PASSWORD");
      if(!configured) return json({error:"Admin password is not configured on the hosting environment."},503);
      const a=Buffer.from(String(password||"")),b=Buffer.from(configured);
      if(a.length!==b.length||!crypto.timingSafeEqual(a,b)) return json({error:"Incorrect password."},401);
      return json({token:sign({exp:Date.now()+8*60*60*1000})});
    }
    const isAdmin=verify((req.headers.get("authorization")||"").replace(/^Bearer\s+/i,""));
    if(["products","stories","settings"].includes(resource)){
      const key=resource;
      if(req.method==="GET") return json((await read(key)) || (resource==="settings"?{}:{items:[]}));
      if(!isAdmin) return json({error:"Administrator sign-in required."},401);
      if(resource==="settings"&&req.method==="PUT"){const incoming=await req.json();const current=(await read(key))||{};const clean={...current};for(const k of ["businessName","whatsapp","currency","email","location","social","instagram","facebook","tiktok","about"])if(k in incoming)clean[k]=String(incoming[k]).slice(0,5000);await write(key,clean);return json(clean);}
      const data=(await read(key))||{items:[]};data.items=data.items||[];
      if(req.method==="POST"){const item={...await req.json(),id:id(),createdAt:Date.now()};data.items.unshift(item);await write(key,data);return json(item,201);}
      if(resourceId&&req.method==="PUT"){const i=data.items.findIndex(x=>x.id===resourceId);if(i<0)return json({error:"Item not found."},404);data.items[i]={...data.items[i],...await req.json(),id:resourceId,updatedAt:Date.now()};await write(key,data);return json(data.items[i]);}
      if(resourceId&&req.method==="DELETE"){data.items=data.items.filter(x=>x.id!==resourceId);await write(key,data);return json({success:true});}
    }
    return json({error:"Route not found."},404);
  } catch(e) { console.error(e); return json({error:"Server error. Please try again."},500); }
};