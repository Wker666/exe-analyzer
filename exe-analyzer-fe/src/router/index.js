import Vue from 'vue'
import Router from 'vue-router'
import Graph from '@/views/Graph'

Vue.use(Router)

export default new Router({
  routes: [
    {
      path: '/',
      name: 'Graph',
      component: Graph
    }
  ]
})
