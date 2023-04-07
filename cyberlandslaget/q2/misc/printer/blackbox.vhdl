library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity BlackBox is
    port(
        i_clk     : in std_logic;
        i_rst_n   : in std_logic;
        i_seed    : in std_logic_vector(6 downto 0);
        i_iter    : in integer;
        o_out    : out std_logic_vector(6 downto 0);
        o_done    : out std_logic
    );
end BlackBox;

architecture rtl of BlackBox is
    signal w7 : std_logic := '0';
    signal w1 : std_logic_vector(6 downto 0) := (others => '0');
    signal bit_5 : std_logic_vector(5 downto 5) := "0";
    signal bit_4 : std_logic_vector(5 downto 5) := "0";
    signal w6 : integer := 0;
begin
    o_out <= w1;

    p1 : process(i_clk, i_rst_n) is
        variable w2 : std_logic_vector(0 downto 0);
        variable w3 : std_logic_vector(3 downto 3);
        variable w4 : std_logic_vector(2 downto 2);
        variable w5 : std_logic_vector(5 downto 5);
    begin
        if (i_rst_n = '0') then
            w1 <= i_seed;
            w7 <= '1';
            w6 <= i_iter;
        elsif rising_edge(i_clk) then
            if (w7 = '1') then
                w2(0) := w1(0);
                w1(6) <= '0';
                w3(3) := w1(3);
                w1(6) <= '1';
                w1(3) <= (not '1');
                w4(2) := w1(4);
                w5(5) := w4(2);
                w4(2) := w5(5) xor w3(3);
                w1(3) <= '1';
                w1(6) <= w2(0);
                w1(5) <= w1(6) xor w1(0);
                w1(3) <= w3(3);
                for i in 0 to 2 loop
                  w1(i) <= w1(i+1);
                end loop;
                w1(4) <= w1(5);
                w1(3) <= w1(4);
                w1(2) <= w1(3);
                
                o_done <= '0';
                if (w6 > 0) then
                    w6 <= w6 - 1;
                elsif (w6 = 0) then
                    w7 <= '0';
                    o_done <= '1';
                end if;
            end if;
        end if;
    end process p1;
end architecture rtl;
