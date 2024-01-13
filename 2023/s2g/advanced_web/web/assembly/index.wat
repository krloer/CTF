(module
  (type (;0;) (func (param i32) (result i32)))
  (type (;1;) (func))
  (type (;2;) (func (param i32)))
  (type (;3;) (func (result i32)))
  (func (;0;) (type 1)
    nop)
  (func (;1;) (type 0) (param i32) (result i32)
    global.get 0
    local.get 0
    i32.sub
    i32.const -16
    i32.and
    local.tee 0
    global.set 0
    local.get 0)
  (func (;2;) (type 2) (param i32)
    local.get 0
    global.set 0)
  (func (;3;) (type 3) (result i32)
    global.get 0)
  (func (;4;) (type 0) (param i32) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32)
    block  ;; label = @1
      block (result i32)  ;; label = @2
        block  ;; label = @3
          block  ;; label = @4
            local.get 0
            local.tee 1
            i32.const 3
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            i32.const 0
            local.get 0
            i32.load8_u
            i32.eqz
            br_if 2 (;@2;)
            drop
            loop  ;; label = @5
              local.get 1
              i32.const 1
              i32.add
              local.tee 1
              i32.const 3
              i32.and
              i32.eqz
              br_if 1 (;@4;)
              local.get 1
              i32.load8_u
              br_if 0 (;@5;)
            end
            br 1 (;@3;)
          end
          loop  ;; label = @4
            local.get 1
            local.tee 3
            i32.const 4
            i32.add
            local.set 1
            local.get 3
            i32.load
            local.tee 2
            i32.const -1
            i32.xor
            local.get 2
            i32.const 16843009
            i32.sub
            i32.and
            i32.const -2139062144
            i32.and
            i32.eqz
            br_if 0 (;@4;)
          end
          loop  ;; label = @4
            local.get 3
            local.tee 1
            i32.const 1
            i32.add
            local.set 3
            local.get 1
            i32.load8_u
            br_if 0 (;@4;)
          end
        end
        local.get 1
        local.get 0
        i32.sub
      end
      i32.const 37
      i32.ne
      br_if 0 (;@1;)
      i32.const 0
      local.set 3
      i32.const 4
      local.set 6
      i32.const 1026
      local.set 5
      block  ;; label = @2
        local.get 0
        local.tee 1
        i32.load8_u
        local.tee 2
        i32.eqz
        br_if 0 (;@2;)
        loop  ;; label = @3
          block  ;; label = @4
            local.get 2
            local.get 5
            i32.load8_u
            local.tee 4
            i32.ne
            br_if 0 (;@4;)
            local.get 4
            i32.eqz
            br_if 0 (;@4;)
            local.get 6
            i32.const 1
            i32.sub
            local.tee 6
            i32.eqz
            br_if 0 (;@4;)
            local.get 5
            i32.const 1
            i32.add
            local.set 5
            local.get 1
            i32.load8_u offset=1
            local.set 2
            local.get 1
            i32.const 1
            i32.add
            local.set 1
            local.get 2
            br_if 1 (;@3;)
            br 2 (;@2;)
          end
        end
        local.get 2
        local.set 3
      end
      local.get 3
      i32.const 255
      i32.and
      local.get 5
      i32.load8_u
      i32.sub
      br_if 0 (;@1;)
      i32.const 1024
      local.set 1
      i32.const 1024
      i32.load8_u
      local.set 4
      block  ;; label = @2
        local.get 0
        i32.const 36
        i32.add
        local.tee 3
        i32.load8_u
        local.tee 2
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        local.get 4
        i32.ne
        br_if 0 (;@2;)
        loop  ;; label = @3
          local.get 1
          i32.load8_u offset=1
          local.set 4
          local.get 3
          i32.load8_u offset=1
          local.tee 2
          i32.eqz
          br_if 1 (;@2;)
          local.get 1
          i32.const 1
          i32.add
          local.set 1
          local.get 3
          i32.const 1
          i32.add
          local.set 3
          local.get 2
          local.get 4
          i32.eq
          br_if 0 (;@3;)
        end
      end
      local.get 2
      local.get 4
      i32.sub
      br_if 0 (;@1;)
      block  ;; label = @2
        local.get 0
        i32.load8_u offset=5
        i32.const 99
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=25
        i32.const 54
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=4
        i32.const 50
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=23
        i32.const 50
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=20
        i32.const 57
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=29
        i32.const 100
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=10
        i32.const 99
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=6
        i32.const 55
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=16
        i32.const 53
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=30
        i32.const 102
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=8
        i32.const 54
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=34
        i32.const 51
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=19
        i32.const 54
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=9
        i32.const 51
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=18
        i32.const 51
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=17
        i32.const 49
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=12
        i32.const 99
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=7
        i32.const 51
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=15
        i32.const 98
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=13
        i32.const 49
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=32
        i32.const 97
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=31
        i32.const 99
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=35
        i32.const 48
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=11
        i32.const 98
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=28
        i32.const 53
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=21
        i32.const 101
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=14
        i32.const 56
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=24
        i32.const 97
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=27
        i32.const 56
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=33
        i32.const 49
        i32.ne
        br_if 0 (;@2;)
        local.get 0
        i32.load8_u offset=26
        i32.const 55
        i32.ne
        br_if 0 (;@2;)
        i32.const 1
        local.set 7
        local.get 0
        i32.load8_u offset=22
        i32.const 49
        i32.eq
        br_if 1 (;@1;)
      end
      i32.const 0
      local.set 7
    end
    local.get 7)
  (table (;0;) 1 1 funcref)
  (memory (;0;) 256 256)
  (global (;0;) (mut i32) (i32.const 66576))
  (export "a" (memory 0))
  (export "b" (func 0))
  (export "c" (func 4))
  (export "d" (table 0))
  (export "e" (func 3))
  (export "f" (func 2))
  (export "g" (func 1))
  (data (;0;) (i32.const 1024) "}\00S2G{"))
