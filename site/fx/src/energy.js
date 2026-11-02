// Gloria FX — сцена «Энергия»: край планеты с орбиты и столбы энергии.
//
// WebGL (three.js) вместо Canvas 2D. Разница не в «красивее», а в том, кто
// считает свет: здесь каждый пиксель столба, атмосферы и искры считает
// видеокарта по шейдеру, а блум (UnrealBloomPass) заставляет всё яркое
// по-настоящему растекаться светом. Canvas 2D умеет только линии и пятна.
//
// Сцена:
//   • звёзды с лёгким мерцанием и параллаксом от наклона телефона;
//   • планета по снимкам NASA: день, терминатор, огни городов ночью,
//     облака, атмосфера;
//   • из точек сети по очереди поднимается луч силы — прямой и ровный,
//     энергия течёт внутри вверх и не разбрызгивается; от основания по
//     поверхности непрерывно расходятся волны и несут пыль энергии.
//     Цвет следует из плотности (синий → голубой → белый), один для всех;
//   • дуга срока над горизонтом: янтарь — оплаченное, зелёный — +30 дней.
//
// Слабое устройство: если кадр дольше ~28 мс, движок сам отключает блум и
// половину искр. `prefers-reduced-motion` — один неподвижный кадр.

import {
  WebGLRenderer, Scene, PerspectiveCamera, Group, Color, Vector2, Vector3,
  Quaternion, Matrix4, SphereGeometry, RingGeometry,
  TorusGeometry, BufferGeometry, Float32BufferAttribute, ShaderMaterial,
  Mesh, Points, PlaneGeometry, AdditiveBlending, NormalBlending, BackSide, DoubleSide, MathUtils,
  TextureLoader, SRGBColorSpace, LinearSRGBColorSpace, LinearMipmapLinearFilter,
} from 'three';
import { EffectComposer } from 'three/examples/jsm/postprocessing/EffectComposer.js';
import { RenderPass } from 'three/examples/jsm/postprocessing/RenderPass.js';
import { UnrealBloomPass } from 'three/examples/jsm/postprocessing/UnrealBloomPass.js';

const R = 10;                       // радиус планеты, условные единицы
const BEAM_H = 6.2;                 // высота столба: одна для всех

// ---------------------------------------------------------------- шейдеры

// Шум: 2D simplex (Ashima / Stefan Gustavson, MIT) и fbm поверх него.
const NOISE = /* glsl */`
vec3 mod289(vec3 x){return x-floor(x*(1./289.))*289.;}
vec2 mod289(vec2 x){return x-floor(x*(1./289.))*289.;}
vec3 permute(vec3 x){return mod289(((x*34.)+1.)*x);}
float snoise(vec2 v){
  const vec4 C=vec4(.211324865405187,.366025403784439,-.577350269189626,.024390243902439);
  vec2 i=floor(v+dot(v,C.yy)); vec2 x0=v-i+dot(i,C.xx);
  vec2 i1=(x0.x>x0.y)?vec2(1.,0.):vec2(0.,1.);
  vec4 x12=x0.xyxy+C.xxzz; x12.xy-=i1; i=mod289(i);
  vec3 p=permute(permute(i.y+vec3(0.,i1.y,1.))+i.x+vec3(0.,i1.x,1.));
  vec3 m=max(.5-vec3(dot(x0,x0),dot(x12.xy,x12.xy),dot(x12.zw,x12.zw)),0.);
  m=m*m; m=m*m;
  vec3 x=2.*fract(p*C.www)-1.; vec3 h=abs(x)-.5; vec3 ox=floor(x+.5); vec3 a0=x-ox;
  m*=1.79284291400159-.85373472095314*(a0*a0+h*h);
  vec3 g; g.x=a0.x*x0.x+h.x*x0.y; g.yz=a0.yz*x12.xz+h.yz*x12.yw;
  return 130.*dot(m,g);
}
float fbm(vec2 p){float f=0.,a=.5;for(int i=0;i<4;i++){f+=a*snoise(p);p*=2.03;a*=.5;}return f;}
`;

// Столб — не цилиндр, а лента, всегда развёрнутая к камере вокруг своей
// оси: так видимую форму целиком рисует фрагментный шейдер.
const BOLT_VERT = /* glsl */`
uniform float uH; uniform float uW;
varying vec2 vUv;
void main(){
  vUv=uv;
  vec3 base=(modelMatrix*vec4(0.,0.,0.,1.)).xyz;
  vec3 ax=normalize(mat3(modelMatrix)*vec3(0.,1.,0.));
  vec3 v=normalize(cameraPosition-(base+ax*uH*.5));
  vec3 side=normalize(cross(ax,v));
  vec3 wp=base+ax*(position.y*uH)+side*(position.x*uW);
  gl_Position=projectionMatrix*viewMatrix*vec4(wp,1.);
}`;

// Луч силы: строго прямой и ровный — энергия не разбрызгивается, а
// течёт внутри вверх. Тонкое белое ядро, плотное свечение вокруг и
// широкий мягкий ореол; по ядру снизу вверх бегут сгустки — видно, что
// сила идёт из точки. Цвет следует из плотности: ореол синий, ближе к оси
// голубой, ядро белое. К вершине луч не рвётся, а растворяется.
const BOLT_FRAG = /* glsl */`
uniform float uTime; uniform float uPower; uniform float uSeed; uniform float uGrow; uniform float uH; uniform float uW;
varying vec2 vUv;
${NOISE}
vec3 plasma(float e){
  vec3 c=mix(vec3(.06,.10,.55),vec3(.18,.46,1.),smoothstep(0.,.5,e));
  c=mix(c,vec3(.66,.88,1.),smoothstep(.5,1.2,e));
  c=mix(c,vec3(1.),smoothstep(1.2,2.2,e));
  return c*e;
}
void main(){
  float y=vUv.y; if(y>uGrow) discard;
  float h=y*uH, t=uTime;
  float x=abs((vUv.x*2.-1.)*uW);
  float flow=snoise(vec2(uSeed, h*.55-t*3.2))*.5+.5;
  float pulse=.85+.15*sin(h*2.2-t*9.+uSeed);
  float core=exp(-pow(x/.045,2.))*(1.6+.5*flow);
  float inner=exp(-pow(x/.13,2.))*(.6+.3*flow)*pulse;
  float halo=exp(-x/.4)*.16;
  float base=exp(-y*14.)*exp(-pow(x/.22,2.))*.45;
  float fade=(1.-smoothstep(.55,1.,y/max(uGrow,.001)))*smoothstep(0.,.015,y);
  float breathe=.94+.06*sin(t*1.7+uSeed);
  float e=(core+inner+halo+base)*fade*uPower*breathe;
  gl_FragColor=vec4(plasma(e),1.);
}`;

// Ударная волна на поверхности: кольцо расходится от основания.
// Волны у основания: от точки по поверхности непрерывно расходятся
// кольца — давление силы. Первая, при рождении луча, — сильнее и шире.
// Края колец чуть неровные (шум по углу), чтобы не выглядеть циркулем.
const RING_FRAG = /* glsl */`
uniform float uAge; uniform float uPower; uniform float uTime;
varying vec2 vUv;
${NOISE}
void main(){
  vec2 p=vUv*2.-1.; float r=length(p); float ang=atan(p.y,p.x);
  float rr=r+snoise(vec2(cos(ang)*2.,sin(ang)*2.)+uTime*.4)*.025;
  float w=0.;
  for(int k=0;k<3;k++){
    float ph=fract(uAge/2.1+float(k)/3.);
    w+=exp(-pow((rr-ph)*mix(34.,16.,ph),2.))*pow(1.-ph,1.6)*.7;
  }
  float b=clamp(uAge/1.3,0.,1.);
  w+=exp(-pow((rr-b)*mix(26.,9.,b),2.))*pow(1.-b,1.3)*1.6;
  float pool=exp(-r*r*90.)*.45;
  float e=(w+pool)*uPower*(1.-smoothstep(.85,1.,r));
  vec3 c=mix(vec3(.16,.42,1.),vec3(.8,.93,1.),smoothstep(.4,1.2,e));
  gl_FragColor=vec4(c*e,1.);
}`;
const PLAIN_VERT = /* glsl */`varying vec2 vUv; void main(){vUv=uv; gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.);}`;

// Искры: каждая летит вверх по столбу по своей фазе.
// Пыль энергии: волны несут её по поверхности от точки наружу.
const SPARK_VERT = /* glsl */`
attribute float aPhase; attribute float aSpeed; attribute float aAng; attribute float aRad;
uniform float uTime; uniform float uPower; uniform float uH; uniform float uPx;
varying float vA;
void main(){
  float t=fract(aPhase+uTime*aSpeed*.45);
  float r=.15+t*3.;
  vec3 p=vec3(cos(aAng)*r, .03+aRad*.25*(1.-t), sin(aAng)*r);
  vA=(1.-t)*smoothstep(0.,.08,t)*uPower;
  vec4 mv=modelViewMatrix*vec4(p,1.);
  gl_PointSize=uPx*.9/-mv.z;
  gl_Position=projectionMatrix*mv;
}`;
const SPARK_FRAG = /* glsl */`
varying float vA;
void main(){
  float d=length(gl_PointCoord-.5); float a=smoothstep(.5,0.,d)*vA;
  gl_FragColor=vec4(vec3(.55,.78,1.)*a,1.);
}`;

// 3D-шум для облаков: value noise по хешу, без швов на сфере.
const NOISE3 = /* glsl */`
float h3(vec3 p){p=fract(p*.3183099+.1);p*=17.;return fract(p.x*p.y*p.z*(p.x+p.y+p.z));}
float n3(vec3 x){vec3 i=floor(x),f=fract(x);f=f*f*(3.-2.*f);
  return mix(mix(mix(h3(i),h3(i+vec3(1,0,0)),f.x),mix(h3(i+vec3(0,1,0)),h3(i+vec3(1,1,0)),f.x),f.y),
             mix(mix(h3(i+vec3(0,0,1)),h3(i+vec3(1,0,1)),f.x),mix(h3(i+vec3(0,1,1)),h3(i+vec3(1,1,1)),f.x),f.y),f.z);}
float fbm3(vec3 p){float f=0.,a=.5;for(int i=0;i<5;i++){f+=a*n3(p);p=p*2.02+vec3(1.7,9.2,3.1);a*=.5;}return f;}
`;

// Земля: снимки NASA (Blue Marble — день, Black Marble — ночные огни, маска
// воды). Солнце сбоку: день, золотистый закат на терминаторе, ночью горят
// города. Вода бликует, суша — нет. Вокруг горящих столбов поверхность
// подсвечивается их цветом. uTex — плавное появление, пока грузятся снимки.
const EARTH_VERT = /* glsl */`
varying vec3 vP; varying vec3 vN; varying vec3 vV;
void main(){
  vP=normalize(position);
  vec4 wp=modelMatrix*vec4(position,1.);
  vN=normalize(mat3(modelMatrix)*normal);
  vV=normalize(cameraPosition-wp.xyz);
  gl_Position=projectionMatrix*viewMatrix*wp;
}`;
const EARTH_FRAG = /* glsl */`
uniform sampler2D uDay; uniform sampler2D uNight; uniform sampler2D uWater;
uniform vec3 uSun; uniform float uTex;
uniform vec3 uHot[12]; uniform vec3 uHotCol[12]; uniform float uHotPow[12];
varying vec3 vP; varying vec3 vN; varying vec3 vV;
vec3 tex(sampler2D t, vec2 uv, vec2 uv2){
  // Шов на 180° долготы: берём ту из двух развёрток, где u не прыгает.
  vec2 dx=dFdx(uv), dy=dFdy(uv), dx2=dFdx(uv2), dy2=dFdy(uv2);
  bool alt=abs(dx.x)+abs(dy.x)>abs(dx2.x)+abs(dy2.x);
  return alt?textureGrad(t,uv2,dx2,dy2).rgb:textureGrad(t,uv,dx,dy).rgb;
}
void main(){
  float lat=asin(clamp(vP.y,-1.,1.)), lon=atan(-vP.z,vP.x);
  vec2 uv=vec2(lon/6.2831853+.5, lat/3.1415927+.5);
  vec2 uv2=vec2(fract(uv.x+.5)-.5, uv.y);
  vec3 day=tex(uDay,uv,uv2), night=tex(uNight,uv,uv2);
  float water=tex(uWater,uv,uv2).r;
  vec3 N=normalize(vN), V=normalize(vV), L=normalize(uSun);
  float ndl=dot(N,L);
  float dayAmt=smoothstep(-.08,.22,ndl);
  vec3 col=day*day*(max(ndl,0.)*1.25+.015)*dayAmt;
  // Блик солнца на воде.
  float sp=pow(max(dot(reflect(-L,N),V),0.),55.)*water;
  col+=vec3(1.,.9,.75)*sp*.9*dayAmt;
  // Огни городов на ночной стороне — тёплые, ярче к ночи.
  // На ночном снимке суша подсвечена синим «лунным светом», огни городов —
  // оранжевые. Огни выделяются по цвету, луна остаётся приглушённым фоном.
  float lights=clamp((night.r-night.b*.85)*3.2,0.,1.);
  lights=pow(lights,1.25);
  vec3 moon=night*night*.55;
  col+=(moon+vec3(1.,.7,.36)*lights*2.2)*(1.-dayAmt);
  // Закат на терминаторе.
  col+=vec3(1.,.42,.12)*exp(-pow((ndl-.02)*14.,2.))*.1*(1.-water*.6);
  // Подсветка от столбов энергии.
  for(int i=0;i<12;i++){ float d=distance(vP*${R.toFixed(1)},uHot[i]); col+=uHotCol[i]*uHotPow[i]*exp(-d*d*1.6)*.28; }
  // Атмосферная дымка по краю диска, голубая днём.
  float f=pow(1.-max(dot(N,V),0.),3.);
  col+=mix(vec3(.35,.3,.6),vec3(.35,.6,1.),dayAmt)*f*(.04+.45*dayAmt);
  gl_FragColor=vec4(col*uTex,1.);
}`;

// Облака: процедурные, на своей оболочке, плывут быстрее планеты. Днём
// белые с тенью рельефа шума, на закате розовеют, ночью почти не видны.
const CLOUD_VERT = EARTH_VERT;
const CLOUD_FRAG = /* glsl */`
uniform vec3 uSun; uniform float uTime; uniform float uTex;
varying vec3 vP; varying vec3 vN; varying vec3 vV;
${NOISE3}
void main(){
  vec3 q=vP*3.2+vec3(uTime*.01,0.,0.);
  float warp=fbm3(q*1.3);
  float c=fbm3(q+warp*1.6);
  // Пояса: меньше облаков в субтропиках, больше у экватора и в умеренных.
  float lat=abs(vP.y);
  float belt=.55+.25*cos(lat*9.)-.2*smoothstep(.85,1.,lat);
  float cov=smoothstep(.48,.72,c*belt+.18);
  float ndl=dot(normalize(vN),normalize(uSun));
  float lit=smoothstep(-.15,.3,ndl);
  vec3 col=mix(vec3(1.,.55,.32),vec3(1.),smoothstep(0.,.35,ndl))*lit*(.55+.45*smoothstep(.4,.9,c));
  col+=vec3(.06,.05,.08)*(1.-lit);
  float a=cov*.85*uTex;
  gl_FragColor=vec4(col*a,a);
}`;

// Атмосфера: оболочка изнутри. Голубая на дневной стороне, оранжевая на
// закате, на ночной почти исчезает — как на снимках с орбиты.
const ATMO_FRAG = /* glsl */`
uniform vec3 uSun;
varying vec3 vN; varying vec3 vV; varying vec2 vUv;
void main(){
  float k=max(-dot(vN,vV),0.);
  float i=pow(k,2.6);
  float ndl=dot(vN,normalize(uSun));
  vec3 c=mix(vec3(1.,.48,.16),vec3(.36,.62,1.),smoothstep(-.05,.45,ndl));
  float side=.12+.88*smoothstep(-.35,.25,ndl);
  gl_FragColor=vec4(c*i*side*.9,i*side*.9);
}`;
const SHELL_VERT = /* glsl */`
varying vec3 vN; varying vec3 vV; varying vec2 vUv;
void main(){ vUv=uv; vec4 wp=modelMatrix*vec4(position,1.); vN=normalize(mat3(modelMatrix)*normal); vV=normalize(cameraPosition-wp.xyz); gl_Position=projectionMatrix*viewMatrix*wp; }`;

const STAR_VERT = /* glsl */`
attribute float aRnd; uniform float uTime; uniform float uPx; varying float vA;
void main(){ vA=.35+.65*(.5+.5*sin(uTime*(.6+aRnd*2.)+aRnd*50.)); vec4 mv=modelViewMatrix*vec4(position,1.); gl_PointSize=uPx*(.6+aRnd*1.2); gl_Position=projectionMatrix*mv; }`;
const STAR_FRAG = /* glsl */`varying float vA; void main(){ float d=length(gl_PointCoord-.5); float a=smoothstep(.5,0.,d)*vA; gl_FragColor=vec4(vec3(1.,.95,.88)*a,a); }`;

// Дуга срока: тонкая светящаяся линия над горизонтом.
const ARC_FRAG = /* glsl */`
uniform float uSplit; uniform float uTime; varying vec2 vUv;
void main(){
  float u=vUv.x;
  vec3 c=u<uSplit?vec3(1.,.73,.36):vec3(.44,.88,.66);
  float glint=exp(-pow((u-mix(uSplit,1.,fract(uTime*.25)))*40.,2.))*step(uSplit,u);
  float a=.9+glint*2.;
  gl_FragColor=vec4((c+glint)*a,a);
}`;

// ---------------------------------------------------------------- геометрия

function latLon(lat, lon, r) {
  const a = lat * Math.PI / 180, b = lon * Math.PI / 180;
  return new Vector3(Math.cos(a) * Math.cos(b) * r, Math.sin(a) * r, -Math.cos(a) * Math.sin(b) * r);
}

function sparkGeometry(n) {
  const ph = [], sp = [], an = [], ra = [], pos = [];
  for (let i = 0; i < n; i++) {
    ph.push(Math.random()); sp.push(0.25 + Math.random() * 0.45);
    an.push(Math.random() * Math.PI * 2); ra.push(0.03 + Math.random() * 0.12);
    pos.push(0, 0, 0);
  }
  const g = new BufferGeometry();
  g.setAttribute('position', new Float32BufferAttribute(pos, 3));
  g.setAttribute('aPhase', new Float32BufferAttribute(ph, 1));
  g.setAttribute('aSpeed', new Float32BufferAttribute(sp, 1));
  g.setAttribute('aAng', new Float32BufferAttribute(an, 1));
  g.setAttribute('aRad', new Float32BufferAttribute(ra, 1));
  return g;
}

const hex = (c) => new Color(`rgb(${c})`);

// ---------------------------------------------------------------- сцена

/**
 * Смонтировать сцену в <canvas>.
 * @param {HTMLCanvasElement} canvas
 * @param {{points: {lat:number, lon:number, color:string, name?:string, server?:boolean}[],
 *          you: {lat:number, lon:number, color:string}, paid?: number,
 *          onLabels?: (labels:{name:string,x:number,y:number,server:boolean}[])=>void}} opts
 */
export function mountEnergy(canvas, opts) {
  const reduced = typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;
  const renderer = new WebGLRenderer({ canvas, antialias: false, alpha: false, powerPreference: 'high-performance' });
  const dpr = Math.min(1.75, window.devicePixelRatio || 1);
  renderer.setPixelRatio(dpr);
  // Все цвета в шейдерах — уже экранные. Без перевода в sRGB: иначе блум на
  // выходе осветлял тёмное небо до серого (так и было в первой версии).
  renderer.outputColorSpace = LinearSRGBColorSpace;
  renderer.setClearColor(new Color(0x060507).convertSRGBToLinear(), 1);

  const scene = new Scene();
  const camera = new PerspectiveCamera(42, 1, 0.1, 400);
  camera.position.set(0, 3.4, 19);
  camera.lookAt(0, 2.7, 0);

  // Звёзды.
  {
    const pos = [], rnd = [];
    for (let i = 0; i < 1600; i++) {
      const v = new Vector3(Math.random() * 2 - 1, Math.random() * 1.2 - 0.1, -Math.random()).normalize().multiplyScalar(150);
      pos.push(v.x, v.y, v.z); rnd.push(Math.random());
    }
    const g = new BufferGeometry();
    g.setAttribute('position', new Float32BufferAttribute(pos, 3));
    g.setAttribute('aRnd', new Float32BufferAttribute(rnd, 1));
    var stars = new Points(g, new ShaderMaterial({
      vertexShader: STAR_VERT, fragmentShader: STAR_FRAG, transparent: true, depthWrite: false,
      blending: AdditiveBlending, uniforms: { uTime: { value: 0 }, uPx: { value: 1.6 * dpr } },
    }));
    scene.add(stars);
  }

  // Планета: группа в центре сферы, сфера ниже кадра — видна шапка.
  const planet = new Group();
  planet.position.set(0, -R, 0);
  scene.add(planet);
  const earth = new Group();        // вращается вокруг своей оси
  planet.add(earth);

  // Солнце сбоку и чуть сзади: Европа у терминатора — в сумерках, с огнями,
  // а дневная сторона видна по левому краю. Солнце неподвижно, Земля под
  // ним вращается — терминатор ползёт по материкам, как настоящий.
  const sun = new Vector3(-1, 0.22, -0.62).normalize();

  const hot = Array.from({ length: 12 }, () => new Vector3(0, 999, 0));
  const hotCol = Array.from({ length: 12 }, () => new Vector3());
  const hotPow = new Array(12).fill(0);

  const texBase = opts.texBase || 'fx/tex/';
  const loader = new TextureLoader();
  const earthU = {
    uDay: { value: null }, uNight: { value: null }, uWater: { value: null },
    uSun: { value: sun }, uTex: { value: 0 },
    uHot: { value: hot }, uHotCol: { value: hotCol }, uHotPow: { value: hotPow },
  };
  let texLoaded = 0, texShownAt = -1;
  const tex = (name, srgb) => loader.load(texBase + name, (t) => {
    t.anisotropy = 4; t.minFilter = LinearMipmapLinearFilter;
    if (srgb) t.colorSpace = SRGBColorSpace;
    texLoaded++;
  });
  earthU.uDay.value = tex('day.jpg', false);
  earthU.uNight.value = tex('night.jpg', false);
  earthU.uWater.value = tex('water.jpg', false);

  const surface = new Mesh(new SphereGeometry(R, 128, 128), new ShaderMaterial({
    vertexShader: EARTH_VERT, fragmentShader: EARTH_FRAG, uniforms: earthU,
  }));
  earth.add(surface);

  const clouds = new Mesh(new SphereGeometry(R * 1.008, 96, 96), new ShaderMaterial({
    vertexShader: CLOUD_VERT, fragmentShader: CLOUD_FRAG, transparent: true, depthWrite: false,
    blending: NormalBlending, premultipliedAlpha: true,
    uniforms: { uSun: { value: sun }, uTime: { value: 0 }, uTex: earthU.uTex },
  }));
  planet.add(clouds);

  const atmo = new Mesh(new SphereGeometry(R * 1.1, 96, 96), new ShaderMaterial({
    vertexShader: SHELL_VERT, fragmentShader: ATMO_FRAG, transparent: true, depthWrite: false,
    side: BackSide, blending: AdditiveBlending, uniforms: { uSun: { value: sun } },
  }));
  planet.add(atmo);

  // Повернуть так, чтобы Европа — между Москвой и Хельсинки — смотрела
  // в камеру с верхушки планеты.
  {
    const focus = latLon(57, 31, 1).normalize();
    const target = new Vector3(0, 0.93, 0.36).normalize();
    planet.quaternion.copy(new Quaternion().setFromUnitVectors(focus, target));
    // Довернуть вокруг target, чтобы север смотрел вдаль, а не вбок.
    const north = new Vector3(0, 1, 0).applyQuaternion(planet.quaternion);
    const want = new Vector3(0, 0, -1);
    const proj = (v) => v.clone().sub(target.clone().multiplyScalar(v.dot(target))).normalize();
    const a = proj(north), b = proj(want);
    let ang = Math.acos(MathUtils.clamp(a.dot(b), -1, 1));
    if (new Vector3().crossVectors(a, b).dot(target) < 0) ang = -ang;
    planet.quaternion.premultiply(new Quaternion().setFromAxisAngle(target, ang));
  }

  // Дуга срока: в плоскости, обращённой к камере, чуть выше края.
  const arcMat = new ShaderMaterial({
    vertexShader: PLAIN_VERT, fragmentShader: ARC_FRAG, transparent: true, depthWrite: false,
    blending: AdditiveBlending, uniforms: { uSplit: { value: 0 }, uTime: { value: 0 } },
  });
  const arcSpan = 0.95;
  // Тор единичного радиуса: масштаб и место считаются по контуру планеты,
  // каким его видит камера (центр смещён к камере на R²/d).
  const arc = new Mesh(new TorusGeometry(1, 0.0034, 8, 160, arcSpan), arcMat);
  scene.add(arc);
  const placeArc = () => {
    const c = planet.position, toCam = camera.position.clone().sub(c), d = toCam.length();
    const rl = R * Math.sqrt(1 - (R * R) / (d * d));
    arc.position.copy(c).add(toCam.normalize().multiplyScalar((R * R) / d));
    arc.scale.setScalar(rl * 1.035);
    arc.lookAt(camera.position);
    arc.rotateZ(Math.PI / 2 - arcSpan / 2);
  };
  placeArc();

  // Точки сети и столбы.
  const all = [{ ...opts.you, you: true, name: 'Вы' }, ...opts.points];
  const sparksPer = 70;
  const nodes = all.map((p, i) => {
    const dir = latLon(p.lat, p.lon, 1).normalize();
    const anchor = new Group();
    anchor.position.copy(dir.clone().multiplyScalar(R * 1.002));
    anchor.quaternion.setFromUnitVectors(new Vector3(0, 1, 0), dir);
    earth.add(anchor);
    const BW = 1.3;
    const boltGeo = new PlaneGeometry(2, 1, 1, 1); boltGeo.translate(0, 0.5, 0);
    const beam = new Mesh(boltGeo, new ShaderMaterial({
      vertexShader: BOLT_VERT, fragmentShader: BOLT_FRAG, transparent: true, depthWrite: false, blending: AdditiveBlending, side: DoubleSide,
      uniforms: { uTime: { value: 0 }, uPower: { value: 0 }, uSeed: { value: i * 7.13 }, uGrow: { value: 0 }, uH: { value: BEAM_H }, uW: { value: BW } },
    }));
    beam.frustumCulled = false;
    const ring = new Mesh(new RingGeometry(0, 3.2, 64), new ShaderMaterial({
      vertexShader: PLAIN_VERT, fragmentShader: RING_FRAG, transparent: true, depthWrite: false, blending: AdditiveBlending, side: DoubleSide,
      uniforms: { uAge: { value: 0 }, uPower: { value: 0 }, uTime: { value: 0 } },
    }));
    ring.rotation.x = -Math.PI / 2; ring.position.y = 0.01;
    // UV кольца — по квадрату, не по радиусу: пересчитать в [0,1]×[0,1].
    { const g = ring.geometry, pa = g.attributes.position, uv = g.attributes.uv;
      for (let k = 0; k < pa.count; k++) uv.setXY(k, pa.getX(k) / 6.4 + 0.5, pa.getY(k) / 6.4 + 0.5); }
    const sparks = new Points(sparkGeometry(sparksPer), new ShaderMaterial({
      vertexShader: SPARK_VERT, fragmentShader: SPARK_FRAG, transparent: true, depthWrite: false, blending: AdditiveBlending,
      uniforms: { uTime: { value: 0 }, uPower: { value: 0 }, uH: { value: BEAM_H * 0.9 }, uPx: { value: 30 * dpr } },
    }));
    anchor.add(beam, ring, sparks);
    anchor.visible = false;
    return { p, i, dir, anchor, beam, ring, sparks };
  });

  // Блум.
  const composer = new EffectComposer(renderer);
  composer.addPass(new RenderPass(scene, camera));
  const bloom = new UnrealBloomPass(new Vector2(256, 256), 0.7, 0.55, 0.42);
  if (!opts.noBloom) composer.addPass(bloom);
  // Без OutputPass: цвета в шейдерах заданы как видимые на экране, и
  // повторный перевод в sRGB осветлял тёмное небо и планету до серого.

  let w = 0, h = 0;
  function resize() {
    const cw = canvas.clientWidth, ch = canvas.clientHeight;
    if (cw === w && ch === h) return;
    w = cw; h = ch;
    renderer.setSize(w, h, false);
    composer.setSize(w, h);
    bloom.resolution.set(w / 2, h / 2);
    camera.aspect = w / h;
    // Узкий экран — шире угол, чтобы край планеты не обрезался.
    camera.fov = MathUtils.clamp(42 / Math.min(1, camera.aspect / 0.62), 42, 64);
    camera.updateProjectionMatrix();
  }

  // Наклон телефона и палец — лёгкий параллакс.
  const tilt = { x: 0, y: 0, tx: 0, ty: 0 };
  const onMove = (e) => { const r = canvas.getBoundingClientRect(); tilt.tx = ((e.clientX - r.left) / r.width - 0.5) * 2; tilt.ty = ((e.clientY - r.top) / r.height - 0.5) * 2; };
  const onTilt = (e) => { if (e.gamma == null) return; tilt.tx = MathUtils.clamp(e.gamma / 30, -1, 1); tilt.ty = MathUtils.clamp((e.beta - 50) / 30, -1, 1); };
  canvas.addEventListener('pointermove', onMove);
  window.addEventListener('deviceorientation', onTilt);

  let paid = opts.paid || 0;
  const SLOT = 1.25;               // секунд между извержениями
  let raf = 0, running = false, t0 = performance.now(), last = 0, slowFrames = 0, lite = false;
  const v3 = new Vector3();

  function frame(now) {
    if (running && !reduced) raf = requestAnimationFrame(frame);
    const dt = now - last; last = now;
    // Адаптация: 40 кадров подряд медленнее ~28 мс — облегчить.
    if (!lite && dt > 28 && dt < 200) { if (++slowFrames > 40) { lite = true; bloom.enabled = false; } } else slowFrames = Math.max(0, slowFrames - 1);

    resize();
    const t = reduced ? 40 : (now - t0) / 1000;
    earth.rotation.y = reduced ? 0 : t * 0.018;
    tilt.x += (tilt.tx - tilt.x) * 0.04; tilt.y += (tilt.ty - tilt.y) * 0.04;
    camera.position.set(tilt.x * 0.9, 3.4 - tilt.y * 0.5, 19);
    camera.lookAt(0, 2.7, 0);
    stars.rotation.y = tilt.x * 0.03;

    stars.material.uniforms.uTime.value = t;
    clouds.material.uniforms.uTime.value = t;
    clouds.rotation.y = earth.rotation.y * 1.35;
    // Снимки догрузились — проявить планету за 0,8 с, без вспышки.
    if (texLoaded >= 3 && texShownAt < 0) texShownAt = t;
    earthU.uTex.value = texShownAt < 0 ? 0 : Math.min(1, (t - texShownAt) / 0.8 + (reduced ? 1 : 0));
    arcMat.uniforms.uTime.value = t;
    arcMat.uniforms.uSplit.value = paid / (paid + 30);
    placeArc();

    // Извержения по очереди, «Вы» первыми. Фазы: 0–0.5 с — ударная волна
    // и рост столба, до 3 с — пик, дальше ровное бурление на 70 %.
    const labels = [];
    for (const n of nodes) {
      const age = t - n.i * SLOT;
      n.anchor.getWorldPosition(v3);
      const toCam = camera.position.clone().sub(v3).normalize();
      const normal = n.dir.clone().applyQuaternion(earth.getWorldQuaternion(new Quaternion()));
      const visible = normal.dot(toCam) > -0.15;
      n.anchor.visible = age > 0 && visible;
      const slot = n.i < 12 ? n.i : -1;
      if (!n.anchor.visible) { if (slot >= 0) hotPow[slot] = 0; continue; }
      const grow = Math.min(1, age / 0.5);
      const peak = age < 3 ? 1 : 0.7 + 0.3 * Math.exp(-(age - 3) * 0.8);
      const burst = 1 + Math.max(0, 1 - age / 0.7) * 0.6;
      const power = peak;
      const u = n.beam.material.uniforms;
      u.uTime.value = t; u.uPower.value = power; u.uGrow.value = grow; u.uW.value = 1.3 * burst;
      // Волны у основания: первая — при рождении луча, дальше непрерывно.
      n.ring.material.uniforms.uAge.value = age;
      n.ring.material.uniforms.uPower.value = power;
      n.ring.material.uniforms.uTime.value = t;
      n.sparks.material.uniforms.uTime.value = t;
      n.sparks.material.uniforms.uPower.value = grow * (lite ? 0.5 : 1);
      if (slot >= 0) { hot[slot].copy(n.anchor.position); hotCol[slot].set(0.32, 0.58, 1.0); hotPow[slot] = power * grow; }
      if (n.p.you || n.p.server) {
        const s = v3.clone().project(camera);
        labels.push({ name: n.p.name, server: !!n.p.server, x: (s.x * 0.5 + 0.5) * w, y: (-s.y * 0.5 + 0.5) * h });
      }
    }
    if (opts.onLabels) opts.onLabels(labels);
    composer.render();
  }

  return {
    /** Отрисовать один кадр, не запуская анимацию: шейдеры компилируются
     *  заранее, и первое открытие экрана не дёргается. */
    warm() { frame(performance.now()); },
    start() { if (running) return; running = true; t0 = performance.now(); last = t0; raf = requestAnimationFrame(frame); },
    stop() { running = false; cancelAnimationFrame(raf); },
    setPaid(d) { paid = Math.max(0, d || 0); },
    dispose() {
      this.stop();
      canvas.removeEventListener('pointermove', onMove);
      window.removeEventListener('deviceorientation', onTilt);
      scene.traverse((o) => { if (o.geometry) o.geometry.dispose(); if (o.material) o.material.dispose(); });
      composer.dispose(); renderer.dispose();
    },
  };
}

/** Есть ли WebGL — проверка до загрузки сцены. */
export function supported() {
  try { const c = document.createElement('canvas'); return !!(c.getContext('webgl2') || c.getContext('webgl')); } catch (e) { return false; }
}
