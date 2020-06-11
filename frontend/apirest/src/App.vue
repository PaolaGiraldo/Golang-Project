<template>
  <div class="consulta-container">
    <div class="consulta-container1"></div>
    <form class="consulta-form" id="domain_form" onsubmit="return false" >
      <span class="consulta-textdomain">Dominio</span>
      <button class="consulta-buttondomain" type='button' v-on:click="postreq_consultar()">Consultar</button>
      <button class="consulta-buttonregistro" type='button' v-on:click="postreq_registro()">Registro histórico</button>
      <input
        type="text"
        id="input_domain"
        placeholder="domain.com"
        v-model="domain"
        name = "domain"
        class="consulta-textinputdomain"
      />
      <p class="consulta-textblock" >
      <pre>{{ this.datapost}}</pre>
      </p>
      
    </form>
  </div>
  
</template>


<script>
//import Vue from 'vue'

import axios from 'axios';

 
export default {
  name: 'Consulta',
  props: {},
data() {
  return {
    domain: null,
    output:null,
    datapost: null,
  }
},
  
  methods: {

    postreq_registro: function() {

axios
  .get('http://localhost:8082/db')
  .then(response => (this.datapost = response.data))
  .catch(error => console.log(error))
   

    console.log("request done")
     console.log(this.info)
     this.output = JSON.stringify(this.datapost);
     
    },
 
 postreq_consultar: function() {


if (this.domain!=null){


axios.post('http://localhost:8082/ssl/host='+ this.domain)
.then(response => (this.datapost = response.data))
  .catch(error => console.log(error))
  
    console.log("request done")
    this.output = JSON.stringify(this.datapost);

 }
 else{
   window.alert("Ingrese un dominio válido");
 }
}
 

  }





}

</script>

<style scoped>
.consulta-container {
  width: 100%;
  display: flex;
  overflow: auto;
  min-height: 100%;
  align-items: center;
  flex-direction: column;
  justify-content: flex-start;
}
.consulta-container1 {
  top: 0px;
  left: 0px;
  width: 100%;
  height: 100%;
  display: flex;
  position: absolute;
  align-items: center;
  flex-direction: column;
  justify-content: center;
  background-color: rgba(255,255,255, 0);
}
@media(max-width: 767px) {
  .consulta-container1 {
    width: 100%;
    height: 1372px;
    position: relative;
  }
}
@media(max-width: 479px) {
  .consulta-container1 {
    width: 100%;
    height: 1336px;
  }
}
.consulta-form {
  top: 10%;
  left: 10%;
  right: px;
  width: 80%;
  bottom: %;
  height: 70%;
  position: absolute;
  align-self: stretch;
}
@media(max-width: 991px) {
  .consulta-form {
    top: 10%;
    left: 10%;
    width: 80%;
    bottom: %;
    height: 70%;
    position: absolute;
    border-width: 2px;
  }
}
@media(max-width: 767px) {
  .consulta-form {
    top: 10%;
    left: 10%;
    bottom: %;
    position: absolute;
    align-self: flex-start;
  }
}
@media(max-width: 479px) {
  .consulta-form {
    top: 10%;
    left: 10%;
    width: 80%;
    bottom: 0%;
    height: 80%;
    position: absolute;
    align-self: center;
  }
}
.consulta-textdomain {
  top: 30px;
  left: 10px;
  position: relative;
  margin-top: 2px;
  margin-left: 10px;
  margin-right: 10px;
  margin-bottom: 10px;
}
@media(max-width: 767px) {
  .consulta-textdomain {
    top: 50px;
    left: 20px;
    position: relative;
  }
}
.consulta-buttondomain {
  top: 200px;
  left: -20px;
  bottom: px;
  display: inline;
  position: relative;
}
@media(max-width: 479px) {
  .consulta-buttondomain {
    left: -40px;
  }
}
.consulta-buttonregistro {
  top: 200px;
  left: 20px;
  bottom: px;
  display: inline;
  position: relative;
}
@media(max-width: 479px) {
  .consulta-buttonregistro {
    top: 250px;
    left: 35px;
    position: absolute;
  }
}
.consulta-textinputdomain {
  top: 80px;
  left: 50px;
  display: inline;
  position: absolute;
}
@media(max-width: 479px) {
  .consulta-textinputdomain {
    left: 10px;
    display: inline;
    position: relative;
  }
}
.consulta-textblock {
  top: 10px;
  left: 40%;
  width: 50%;
  height: 80%;
  position: relative;
}
@media(max-width: 991px) {
  .consulta-textblock {
    top: 10%;
    left: 55%;
    width: 40%;
    height: 80%;
    opacity: 1;
    position: absolute;
    font-family: Lucida Console;
  }
}
@media(max-width: 767px) {
  .consulta-textblock {
    top: 40%;
    left: 10%;
    width: 50%;
    height: 80%;
    position: relative;
  }
}
@media(max-width: 479px) {
  .consulta-textblock {
    top: 40%;
    left: 10%;
    width: 70%;
    height: 50%;
  }
}
</style>
