library ieee;
use ieee.std_logic_1164.all;
use ieee.std_logic_arith.all;
use ieee.std_logic_unsigned.all;

entity cnt_tb is
end cnt_tb;

architecture bh of cnt_tb is
    component FlagPrinter is
        port(
            i_clk           : in std_logic;
            i_addr          : in std_logic_vector(5 downto 0);
            i_read          : in std_logic;
            o_read_done     : out std_logic;
            o_flag_byte     : out std_logic_vector(6 downto 0)
        );
    end component;

    signal clk: std_logic := '0';
    signal rd: std_logic := '0';
    signal q : std_logic_vector(7 downto 0);

begin
    printer: FlagPrinter port map (
        i_clk           => clk,
        i_addr          => "000000",
        i_read          => rd,
        o_read_done     => q(0),
        o_flag_byte     => q(6 downto 0)
    );
    
    clock: process
    begin
        wait for 100 ps;
        rd <= not rd;
        for loop_var in 500 downto 0 loop
            clk <= not  clk;
            wait for 10 ps;
        end loop;
    end process;
end bh;