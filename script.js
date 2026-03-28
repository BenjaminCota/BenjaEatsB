/**
 * prototipo-delivery-b/script.js — Variante B (A/B)
 * Misma lógica que delivery base; UI diferenciada por styles-ab-b.css + HTML.
 */

(function () {
  'use strict';

  var RESTAURANTES = [
    { id: 'r1', nombre: 'Pizzería Napoli', categoria: 'pizza', img: './assets/rest-r1.svg' },
    { id: 'r2', nombre: 'Sushi Roll', categoria: 'asiatica', img: './assets/rest-r2.svg' },
    { id: 'r3', nombre: 'Burger Norte', categoria: 'hamburguesas', img: './assets/rest-r3.svg' },
    { id: 'r4', nombre: 'Mamma Mia Express', categoria: 'pizza', img: './assets/rest-r4.svg' }
  ];

  /** Platos por restaurante (cada uno con imagen en ./assets/) */
  var MENU = {
    r1: [
      { id: 'm1', nombre: 'Margarita', precio: 8.5, img: './assets/dish-m1.svg' },
      { id: 'm2', nombre: 'Cuatro quesos', precio: 10.9, img: './assets/dish-m2.svg' }
    ],
    r2: [
      { id: 'm3', nombre: 'Menú maki (12 pzs)', precio: 14.0, img: './assets/dish-m3.svg' },
      { id: 'm4', nombre: 'Yakisoba', precio: 9.5, img: './assets/dish-m4.svg' }
    ],
    r3: [
      { id: 'm5', nombre: 'Clásica + patatas', precio: 11.0, img: './assets/dish-m5.svg' },
      { id: 'm6', nombre: 'Veggie', precio: 10.5, img: './assets/dish-m6.svg' }
    ],
    r4: [
      { id: 'm7', nombre: 'Calzone', precio: 9.0, img: './assets/dish-m7.svg' },
      { id: 'm8', nombre: 'Prosciutto', precio: 11.5, img: './assets/dish-m8.svg' }
    ]
  };

  var restauranteActual = null;
  /** pedido: { idPlato, nombre, precioUnit, cantidad } */
  var pedido = [];

  var elFiltro = document.getElementById('filtro-cat');
  var elListaRest = document.getElementById('lista-restaurantes');
  var elStepRest = document.getElementById('step-restaurante');
  var elStepProd = document.getElementById('step-productos');
  var elStepRes = document.getElementById('step-resumen');
  var elStepConf = document.getElementById('step-confirmacion');
  var elTituloRest = document.getElementById('titulo-restaurante');
  var elListaPlatos = document.getElementById('lista-platos');
  var elListaResumen = document.getElementById('lista-resumen');
  var elResumenVacio = document.getElementById('resumen-vacio');
  var elTotal = document.getElementById('total-delivery');
  var elMsgConfirm = document.getElementById('msg-confirm');

  function mostrarSoloPanel(panel) {
    var panels = [elStepRest, elStepProd, elStepRes, elStepConf];
    for (var i = 0; i < panels.length; i++) {
      var p = panels[i];
      var on = p === panel;
      p.classList.toggle('active', on);
      p.hidden = !on;
    }
    actualizarIndicadoresPasos(panel);
  }

  function actualizarIndicadoresPasos(panel) {
    var n = '0';
    if (panel === elStepRest) n = '1';
    if (panel === elStepProd) n = '2';
    if (panel === elStepRes) n = '3';
    if (panel === elStepConf) n = '3';

    var indicadores = document.querySelectorAll('[data-step-indicator]');
    for (var i = 0; i < indicadores.length; i++) {
      var el = indicadores[i];
      var step = el.getAttribute('data-step-indicator');
      el.classList.toggle('active', step === n || (panel === elStepConf && step === '3'));
    }
  }

  function filtrarRestaurantes() {
    var cat = elFiltro.value;
    elListaRest.innerHTML = '';
    for (var i = 0; i < RESTAURANTES.length; i++) {
      var r = RESTAURANTES[i];
      if (cat !== 'todas' && r.categoria !== cat) continue;
      var li = document.createElement('li');
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'card-rest';
      btn.setAttribute('data-rest', r.id);
      btn.innerHTML =
        '<span class="card-rest__media"><img src="' +
        r.img +
        '" width="72" height="72" alt="" loading="lazy"></span>' +
        '<span class="card-rest__body"><strong>' +
        escapeHtml(r.nombre) +
        '</strong><span class="tag">' +
        escapeHtml(r.categoria) +
        '</span></span>';
      li.appendChild(btn);
      elListaRest.appendChild(li);
    }
  }

  function escapeHtml(s) {
    var d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  function abrirMenu(restId) {
    restauranteActual = restId;
    var r = null;
    for (var i = 0; i < RESTAURANTES.length; i++) {
      if (RESTAURANTES[i].id === restId) {
        r = RESTAURANTES[i];
        break;
      }
    }
    elTituloRest.textContent = r ? r.nombre : 'Menú';
    var platos = MENU[restId] || [];
    elListaPlatos.innerHTML = '';
    for (var j = 0; j < platos.length; j++) {
      var pl = platos[j];
      var li = document.createElement('li');
      li.className = 'plato-row';
      li.innerHTML =
        '<img class="plato-thumb" src="' +
        pl.img +
        '" width="52" height="52" alt="">' +
        '<div class="plato-info"><span class="plato-nombre">' +
        escapeHtml(pl.nombre) +
        '</span></div>' +
        '<span class="plato-precio">' +
        formatEuros(pl.precio) +
        '</span>' +
        '<button type="button" class="btn-mini" data-add-plato="' +
        pl.id +
        '" data-nombre="' +
        escapeAttr(pl.nombre) +
        '" data-precio="' +
        pl.precio +
        '" data-img="' +
        escapeAttr(pl.img) +
        '">+</button>';
      elListaPlatos.appendChild(li);
    }
    mostrarSoloPanel(elStepProd);
  }

  function escapeAttr(s) {
    return String(s).replace(/"/g, '&quot;');
  }

  function lineaPedido(idPlato) {
    for (var i = 0; i < pedido.length; i++) {
      if (pedido[i].idPlato === idPlato) return pedido[i];
    }
    return null;
  }

  function agregarPlato(idPlato, nombre, precio, img) {
    var linea = lineaPedido(idPlato);
    if (linea) {
      linea.cantidad += 1;
    } else {
      pedido.push({
        idPlato: idPlato,
        nombre: nombre,
        precioUnit: precio,
        cantidad: 1,
        img: img
      });
    }
  }

  function totalPedido() {
    var t = 0;
    for (var i = 0; i < pedido.length; i++) {
      t += pedido[i].precioUnit * pedido[i].cantidad;
    }
    return t;
  }

  function formatEuros(n) {
    return Number(n).toFixed(2).replace('.', ',') + ' €';
  }

  function pintarResumen() {
    elListaResumen.innerHTML = '';
    if (pedido.length === 0) {
      elResumenVacio.hidden = false;
    } else {
      elResumenVacio.hidden = true;
    }
    for (var i = 0; i < pedido.length; i++) {
      var l = pedido[i];
      var li = document.createElement('li');
      li.className = 'resumen-line';
      li.innerHTML =
        '<img class="resumen-thumb" src="' +
        l.img +
        '" width="40" height="40" alt="">' +
        '<span class="resumen-nombre">' +
        escapeHtml(l.nombre) +
        ' × ' +
        l.cantidad +
        '</span><span class="resumen-precio">' +
        formatEuros(l.precioUnit * l.cantidad) +
        '</span>';
      elListaResumen.appendChild(li);
    }
    elTotal.textContent = formatEuros(totalPedido());
  }

  elListaRest.addEventListener('click', function (e) {
    var btn = e.target.closest('[data-rest]');
    if (!btn) return;
    abrirMenu(btn.getAttribute('data-rest'));
  });

  elFiltro.addEventListener('change', filtrarRestaurantes);

  elListaPlatos.addEventListener('click', function (e) {
    var b = e.target.closest('[data-add-plato]');
    if (!b) return;
    var id = b.getAttribute('data-add-plato');
    var nombre = b.getAttribute('data-nombre');
    var precio = parseFloat(b.getAttribute('data-precio'), 10);
    var imgPlato = b.getAttribute('data-img') || '';
    agregarPlato(id, nombre, precio, imgPlato);
  });

  document.getElementById('btn-volver-rest').addEventListener('click', function () {
    mostrarSoloPanel(elStepRest);
  });

  document.getElementById('btn-carrito').addEventListener('click', function () {
    pintarResumen();
    mostrarSoloPanel(elStepRes);
  });

  document.getElementById('btn-seguir-comprando').addEventListener('click', function () {
    if (restauranteActual) abrirMenu(restauranteActual);
    else mostrarSoloPanel(elStepRest);
  });

  document.getElementById('btn-comprar').addEventListener('click', function () {
    if (pedido.length === 0) {
      alert('Añada al menos un plato antes de confirmar.');
      return;
    }
    var nombreRest = '';
    for (var i = 0; i < RESTAURANTES.length; i++) {
      if (RESTAURANTES[i].id === restauranteActual) {
        nombreRest = RESTAURANTES[i].nombre;
        break;
      }
    }
    elMsgConfirm.textContent =
      'Su pedido en ' +
      nombreRest +
      ' por ' +
      formatEuros(totalPedido()) +
      ' está en preparación. Tiempo aproximado: 35 minutos.';
    pedido = [];
    pintarResumen();
    mostrarSoloPanel(elStepConf);
  });

  document.getElementById('btn-nuevo').addEventListener('click', function () {
    restauranteActual = null;
    mostrarSoloPanel(elStepRest);
  });

  filtrarRestaurantes();
})();
