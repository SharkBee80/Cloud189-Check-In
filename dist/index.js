import"dotenv/config";var l=process.env.TG,h=process.env.ACCOUNTS,d=(()=>{switch(process.env.Throw){case"true":return!0;case"false":return!1;default:return!0}})();import w from"axios";var u=class{token;chat_id;max_try=3;timeout=5e3;base_url;constructor(r,t,s=3,n=5e3){this.token=r,this.chat_id=t,this.max_try=s,this.timeout=n,this.base_url=`https://api.telegram.org/bot${this.token}/`}async post(r,t){let s=this.base_url+r,n=w.create({baseURL:s,timeout:this.timeout});for(let o=0;o<this.max_try;o++)try{let i=await n.post("",t);return console.log(i.data),{ok:!0,result:i.data}}catch(i){if(o===this.max_try)return console.log(`Telegram API 请求失败,${i}`),{ok:!1,error:i};console.log(`${i}
Telegram API 请求失败，正在第 ${o+1} 次重试...`),await new Promise(c=>setTimeout(c,1e3))}return{ok:!1,error:"Telegram API 请求失败"}}async text(r,t){let s={chat_id:this.chat_id,text:r};return t&&(s.parse_mode=t),this.post("sendMessage",s)}async md(r){return this.text(r,"Markdown")}};import{CloudClient as y}from"cloud189-sdk";var g=class{username;password;client;constructor(r,t,s,n){this.username=r,this.password=t,this.client=new y({username:r,password:t})}async userSign(){return await this.client.userSign()}async info(){return await this.client.getUserSizeInfo()}};async function x(e,r){let t="",s=!1;try{let[n,o]=e;if(!n||!o)throw new Error("Missing Account Or Password");if(!new RegExp(/^(?:(?:\+|00)86)?1\d{10}$/).test(n))throw new Error("Invalid Account");let i=new g(n,o),c=await i.userSign(),f=await i.info(),a={index:r+1,isSign:c.isSign,bonus:c.netdiskBonus,id:f.account.split("@")[0],total:f.cloudCapacityInfo.totalSize};t=`🙍🏻‍♂️ 第${a.index}个账号 ${a.id}
${a.isSign?"☑️":"✅"} 已签到，获得 ${a.bonus}M 空间
总共 ${b(a.total)}
`}catch(n){t=`❌ 第${r+1}个账号 出错
⁉️ ${n}`,s=!0}finally{return console.log(t),[t,s]}}function b(e){return e>1024*1024*1024*1024?(e/(1024*1024*1024*1024)).toFixed(2)+"TB":e>1024*1024*1024?(e/(1024*1024*1024)).toFixed(2)+"GB":e>1024*1024?(e/1024*1024).toFixed(2)+"MB":e+"KB"}async function T(e){let r=0,t=[],s=!1,n=e.replace("；",";").replace("&&",`
`).split(`
`).map(o=>o.split(";"));if(r=n.length,r==0)return{len:r,msg:t,err:s};for(let o=0;o<r;o++){let i=await x(n[o],o);t.push(i[0]),i[1]&&(s=!0)}return{len:r,msg:t,err:s}}function S(e,r){let t=new Date().toLocaleString("zh-CN",{hour12:!1});return`
#ecloud *天翼云盘自动签到*

${e.join(`
`)}

📅 *时间*：${t}
`}async function $(e,r){if(l){let t=S(e,r);console.log(t);let s={};if(l)try{let n=l.replace("；",";").split(";").filter(Boolean);if(n.length!=2||!n[0]||!n[1])throw new Error("Invalid TG config");await new u(n[0],n[1]).md(t).then(i=>{i.error&&(s.tg=i.error)})}catch(n){s.tg=n}return s}return{}}async function v(){let e={};if(!h)throw new Error("No accounts provided");let r=await T(h).then(t=>(t.err&&(e.main=!0),t));if(await $(r.msg,r.len).then(t=>Object.assign(e,t)),Object.keys(e).length&&(console.log(Object.entries(e).join(`
`)),d))throw new Error("Some Error Occured")}v();
