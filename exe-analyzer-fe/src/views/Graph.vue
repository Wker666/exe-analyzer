<template>
    <div>
      <ControlFlowGraphViewer />
    </div>
  </template>
  
  <script>
  import ControlFlowGraphViewer from '@/components/ControlFlowGraphViewer.vue';
  
  export default {
    name: 'Graph',
    components: {
      ControlFlowGraphViewer
    }
  };
  </script>