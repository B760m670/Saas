// Gloria FX — сцена «Энергия»: край планеты с орбиты и столбы энергии.
//
// WebGL (three.js) вместо Canvas 2D. Разница не в «красивее», а в том, кто
// считает свет: здесь каждый пиксель столба, атмосферы и искры считает
// видеокарта по шейдеру, а блум (UnrealBloomPass) заставляет всё яркое
// по-настоящему растекаться светом. Canvas 2D умеет только линии и пятна.
//
// Сцена:
//   • звёзды с лёгким мерцанием и параллаксом от наклона телефона;
//   • планета — тёмная сфера с рассеянием по краю и атмосферой (френель),
//     материки из тысяч светящихся точек по маске суши;
//   • точки сети по очереди извергают столб энергии: ударная волна по
//     поверхности, вспышка, затем столб с раскалённым ядром и текучим шумом
//     внутри, искры несутся вверх; после пика энергия не гаснет, а бурлит
//     ровным потоком. Мощность у всех столбов одна;
//   • дуга срока над горизонтом: янтарь — оплаченное, зелёный — +30 дней.
//
// Слабое устройство: если кадр дольше ~28 мс, движок сам отключает блум и
// половину искр. `prefers-reduced-motion` — один неподвижный кадр.

import {
  WebGLRenderer, Scene, PerspectiveCamera, Group, Color, Vector2, Vector3,
  Quaternion, Matrix4, SphereGeometry, CylinderGeometry, RingGeometry,
  TorusGeometry, BufferGeometry, Float32BufferAttribute, ShaderMaterial,
  Mesh, Points, AdditiveBlending, BackSide, DoubleSide, MathUtils,
} from 'three';
import { EffectComposer } from 'three/examples/jsm/postprocessing/EffectComposer.js';
import { RenderPass } from 'three/examples/jsm/postprocessing/RenderPass.js';
import { UnrealBloomPass } from 'three/examples/jsm/postprocessing/UnrealBloomPass.js';
import { LAND, LAND_W, LAND_H } from './land.js';

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

const BEAM_VERT = /* glsl */`
varying vec2 vUv; varying vec3 vN; varying vec3 vV;
void main(){
  vUv=uv;
  vec4 wp=modelMatrix*vec4(position,1.);
  vN=normalize(mat3(modelMatrix)*normal);
  vV=normalize(cameraPosition-wp.xyz);
  gl_Position=projectionMatrix*viewMatrix*wp;
}`;

// Столб: ядро по френелю (середина цилиндра, обращённая к нам, — белая),
// внутри течёт шум снизу вверх, к вершине гаснет. uPower — 0…1: рост,
// пик, ровное бурление.
const BEAM_FRAG = /* glsl */`
uniform vec3 uColor; uniform float uTime; uniform float uPower; uniform float uSeed; uniform float uGrow;
varying vec2 vUv; varying vec3 vN; varying vec3 vV;
${NOISE}
void main(){
  float y=vUv.y;
  if(y>uGrow) discard;
  float face=abs(dot(vN,vV));
  float core=pow(face,5.);
  float flow=fbm(vec2(vUv.x*6.2832*.8+uSeed, y*3.5-uTime*2.6));
  float streak=smoothstep(.15,.9,fbm(vec2(vUv.x*12.+uSeed*3., y*1.2-uTime*4.)));
  float body=smoothstep(.0,.35,face)*(.55+.45*flow)+streak*.6*face;
  float fade=(1.-smoothstep(.35,1.,y/max(uGrow,.001)))*smoothstep(0.,.04,y);
  vec3 col=uColor*body*1.25+vec3(1.)*core*1.35;
  float a=(body*.9+core)*fade*uPower;
  gl_FragColor=vec4(col*a,a);
}`;

// Ореол вокруг столба — широкий, мягкий, дрожит.
const HALO_FRAG = /* glsl */`
uniform vec3 uColor; uniform float uTime; uniform float uPower; uniform float uSeed; uniform float uGrow;
varying vec2 vUv; varying vec3 vN; varying vec3 vV;
${NOISE}
void main(){
  float y=vUv.y; if(y>uGrow) discard;
  float face=pow(abs(dot(vN,vV)),2.2);
  float n=.7+.3*snoise(vec2(y*2.-uTime*1.5,uSeed));
  float fade=(1.-smoothstep(.3,1.,y/max(uGrow,.001)));
  float a=face*fade*n*.35*uPower;
  gl_FragColor=vec4(uColor*a,a);
}`;

// Ударная волна на поверхности: кольцо расходится от основания.
const RING_FRAG = /* glsl */`
uniform vec3 uColor; uniform float uWave; uniform float uPower;
varying vec2 vUv;
void main(){
  vec2 p=vUv*2.-1.; float r=length(p);
  float ring=exp(-pow((r-uWave)*14.,2.))*(1.-uWave);
  float pool=exp(-r*r*14.)*uPower;
  float a=ring*1.4+pool*.9;
  gl_FragColor=vec4(mix(uColor,vec3(1.),pool*.6)*a,a);
}`;
const PLAIN_VERT = /* glsl */`varying vec2 vUv; void main(){vUv=uv; gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.);}`;

// Искры: каждая летит вверх по столбу по своей фазе.
const SPARK_VERT = /* glsl */`
attribute float aPhase; attribute float aSpeed; attribute float aAng; attribute float aRad;
uniform float uTime; uniform float uPower; uniform float uH; uniform float uPx;
varying float vA;
void main(){
  float t=fract(aPhase+uTime*aSpeed);
  float r=aRad*(1.+t*1.6);
  vec3 p=vec3(cos(aAng+t*3.)*r, t*uH, sin(aAng+t*3.)*r);
  vA=(1.-t)*smoothstep(0.,.05,t)*uPower;
  vec4 mv=modelViewMatrix*vec4(p,1.);
  gl_PointSize=uPx*(1.6+2.4*(1.-t))/-mv.z;
  gl_Position=projectionMatrix*mv;
}`;
const SPARK_FRAG = /* glsl */`
uniform vec3 uColor; varying float vA;
void main(){
  float d=length(gl_PointCoord-.5); float a=smoothstep(.5,0.,d)*vA;
  gl_FragColor=vec4(mix(uColor,vec3(1.),.55)*a,a);
}`;

// Материки: точка ярче к центру диска планеты (обращена к нам) и чуть
// мерцает; рядом с горящим столбом подсвечивается его цветом.
const LAND_VERT = /* glsl */`
attribute float aRnd;
uniform float uTime; uniform float uPx; uniform vec3 uHot[12]; uniform vec3 uHotCol[12]; uniform float uHotPow[12];
varying float vA; varying vec3 vC;
void main(){
  vec4 wp=modelMatrix*vec4(position,1.);
  vec3 n=normalize(wp.xyz-vec3(0.,-${R.toFixed(1)},0.));
  vec3 v=normalize(cameraPosition-wp.xyz);
  float face=dot(n,v);
  vA=smoothstep(-.05,.35,face)*(.55+.45*sin(uTime*1.3+aRnd*40.));
  vec3 c=vec3(1.,.86,.62);
  for(int i=0;i<12;i++){ float d=distance(position,uHot[i]); c+=uHotCol[i]*uHotPow[i]*exp(-d*d*1.4)*1.6; }
  vC=c;
  vec4 mv=viewMatrix*wp;
  gl_PointSize=uPx*(1.+aRnd*.6)/-mv.z;
  gl_Position=projectionMatrix*mv;
}`;
const LAND_FRAG = /* glsl */`
varying float vA; varying vec3 vC;
void main(){ float d=length(gl_PointCoord-.5); float a=smoothstep(.5,.1,d)*vA*.55; gl_FragColor=vec4(vC*a,a); }`;

// Тело планеты: тёмное, с рассеянием света по краю.
const BODY_FRAG = /* glsl */`
varying vec3 vN; varying vec3 vV; varying vec2 vUv;
void main(){
  float f=1.-max(dot(vN,vV),0.);
  vec3 base=mix(vec3(.02,.015,.025),vec3(.07,.045,.065),smoothstep(-.2,.9,vN.y));
  vec3 rim=vec3(.93,.6,.18)*pow(f,6.)*.5;
  gl_FragColor=vec4(base+rim,1.);
}`;
// Атмосфера: оболочка изнутри, свечение уходит в космос.
const ATMO_FRAG = /* glsl */`
varying vec3 vN; varying vec3 vV; varying vec2 vUv;
void main(){
  // Оболочка рисуется изнутри: у края планеты -dot(N,V) велик, к внешнему
  // краю оболочки падает до нуля — свечение плавно уходит в космос.
  float k=max(-dot(vN,vV),0.);
  float i=pow(k,2.2);
  vec3 c=mix(vec3(.5,.3,1.),vec3(1.,.6,.2),pow(k,1.5));
  gl_FragColor=vec4(c*i*.55,i*.55);
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

function landPoints(count) {
  const raw = atob(LAND);
  const isLand = (lat, lon) => {
    const r = Math.min(LAND_H - 1, Math.floor((90 - lat) / 2));
    const c = Math.min(LAND_W - 1, Math.floor((lon + 180) / 2));
    const k = r * LAND_W + c;
    return (raw.charCodeAt(k >> 3) >> (k & 7)) & 1;
  };
  const pos = [], rnd = [];
  const ga = Math.PI * (3 - Math.sqrt(5));
  for (let i = 0; i < count; i++) {
    const y = 1 - (i + 0.5) * 2 / count, th = ga * i;
    const lat = Math.asin(y) * 180 / Math.PI;
    const lon = ((th * 180 / Math.PI) % 360 + 540) % 360 - 180;
    if (lat < -60 || !isLand(lat, lon)) continue;
    const p = latLon(lat, lon, R * 1.002);
    pos.push(p.x, p.y, p.z); rnd.push(Math.random());
  }
  const g = new BufferGeometry();
  g.setAttribute('position', new Float32BufferAttribute(pos, 3));
  g.setAttribute('aRnd', new Float32BufferAttribute(rnd, 1));
  return g;
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
  renderer.setClearColor(0x060507, 1);

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

  const body = new Mesh(new SphereGeometry(R, 96, 96), new ShaderMaterial({ vertexShader: SHELL_VERT, fragmentShader: BODY_FRAG }));
  planet.add(body);
  const atmo = new Mesh(new SphereGeometry(R * 1.12, 96, 96), new ShaderMaterial({
    vertexShader: SHELL_VERT, fragmentShader: ATMO_FRAG, transparent: true, depthWrite: false,
    side: BackSide, blending: AdditiveBlending,
  }));
  planet.add(atmo);

  const hot = Array.from({ length: 12 }, () => new Vector3(0, 999, 0));
  const hotCol = Array.from({ length: 12 }, () => new Vector3());
  const hotPow = new Array(12).fill(0);
  const land = new Points(landPoints(60000), new ShaderMaterial({
    vertexShader: LAND_VERT, fragmentShader: LAND_FRAG, transparent: true, depthWrite: false,
    blending: AdditiveBlending,
    uniforms: { uTime: { value: 0 }, uPx: { value: 19 * dpr }, uHot: { value: hot }, uHotCol: { value: hotCol }, uHotPow: { value: hotPow } },
  }));
  earth.add(land);

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
    const color = hex(p.color);
    const uni = () => ({ uColor: { value: color }, uTime: { value: 0 }, uPower: { value: 0 }, uSeed: { value: i * 7.13 }, uGrow: { value: 0 } });
    const beamGeo = new CylinderGeometry(0.16, 0.28, BEAM_H, 24, 1, true); beamGeo.translate(0, BEAM_H / 2, 0);
    const haloGeo = new CylinderGeometry(0.6, 1.0, BEAM_H, 24, 1, true); haloGeo.translate(0, BEAM_H / 2, 0);
    const beam = new Mesh(beamGeo, new ShaderMaterial({ vertexShader: BEAM_VERT, fragmentShader: BEAM_FRAG, uniforms: uni(), transparent: true, depthWrite: false, blending: AdditiveBlending, side: DoubleSide }));
    const halo = new Mesh(haloGeo, new ShaderMaterial({ vertexShader: BEAM_VERT, fragmentShader: HALO_FRAG, uniforms: uni(), transparent: true, depthWrite: false, blending: AdditiveBlending, side: DoubleSide }));
    const ring = new Mesh(new RingGeometry(0, 1.9, 48), new ShaderMaterial({
      vertexShader: PLAIN_VERT, fragmentShader: RING_FRAG, transparent: true, depthWrite: false, blending: AdditiveBlending, side: DoubleSide,
      uniforms: { uColor: { value: color }, uWave: { value: 1 }, uPower: { value: 0 } },
    }));
    ring.rotation.x = -Math.PI / 2; ring.position.y = 0.01;
    // UV кольца — по квадрату, не по радиусу: пересчитать в [0,1]×[0,1].
    { const g = ring.geometry, pa = g.attributes.position, uv = g.attributes.uv;
      for (let k = 0; k < pa.count; k++) uv.setXY(k, pa.getX(k) / 3.8 + 0.5, pa.getY(k) / 3.8 + 0.5); }
    const sparks = new Points(sparkGeometry(sparksPer), new ShaderMaterial({
      vertexShader: SPARK_VERT, fragmentShader: SPARK_FRAG, transparent: true, depthWrite: false, blending: AdditiveBlending,
      uniforms: { uColor: { value: color }, uTime: { value: 0 }, uPower: { value: 0 }, uH: { value: BEAM_H * 0.9 }, uPx: { value: 30 * dpr } },
    }));
    anchor.add(beam, halo, ring, sparks);
    anchor.visible = false;
    return { p, i, dir, anchor, beam, halo, ring, sparks, color };
  });

  // Блум.
  const composer = new EffectComposer(renderer);
  composer.addPass(new RenderPass(scene, camera));
  const bloom = new UnrealBloomPass(new Vector2(256, 256), 0.7, 0.55, 0.42);
  composer.addPass(bloom);
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
    land.material.uniforms.uTime.value = t;
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
      const burst = 1 + Math.max(0, 1 - age / 0.9) * 0.9;
      const breathe = 0.92 + 0.08 * Math.sin(t * 5 + n.i);
      const power = peak * breathe;
      for (const m of [n.beam, n.halo]) {
        m.material.uniforms.uTime.value = t;
        m.material.uniforms.uPower.value = power;
        m.material.uniforms.uGrow.value = grow;
      }
      n.beam.scale.set(burst, 1, burst); n.halo.scale.set(burst * (1 + 0.06 * Math.sin(t * 9 + n.i)), 1, burst);
      // Волна: первая — при рождении, дальше раз в 2,4 с, слабее.
      const wave = age < 1.4 ? age / 1.4 : ((age - 1.4) % 2.4) / 2.4;
      n.ring.material.uniforms.uWave.value = wave;
      n.ring.material.uniforms.uPower.value = power;
      n.sparks.material.uniforms.uTime.value = t;
      n.sparks.material.uniforms.uPower.value = grow * (lite ? 0.5 : 1);
      if (slot >= 0) { hot[slot].copy(n.anchor.position); hotCol[slot].set(n.color.r, n.color.g, n.color.b); hotPow[slot] = power * grow; }
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
