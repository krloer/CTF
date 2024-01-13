library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity FlagPrinter is
    port(
        i_clk           : in std_logic;
        i_addr          : in std_logic_vector(5 downto 0);
        i_read          : in std_logic;
        o_read_done     : out std_logic;
        o_flag_byte     : out std_logic_vector(6 downto 0)
    );
end FlagPrinter;

architecture rtl of FlagPrinter is
    component BlackBox is
        port(
            i_clk     : in std_logic;
            i_rst_n     : in std_logic;
            i_seed    : in std_logic_vector(6 downto 0);
            i_iter    : in integer;
            o_out    : out std_logic_vector(6 downto 0);
            o_done    : out std_logic
        );
    end component;

    signal w_seed   : std_logic_vector(6 downto 0) := (others => '0');
    signal w_rst    : std_logic := '1';
    signal w_out   : std_logic_vector(6 downto 0) := (others => '0');
    signal w_iter   : integer := 0;
    signal w_done   : std_logic := '0';

begin
    verilog: BlackBox port map (
        i_clk => i_clk,
        i_rst_n => w_rst,
        i_seed => w_seed,
        i_iter => w_iter,
        o_out => w_out,
        o_done => w_done
    );

    o_read_done <= '1' when rising_edge(w_done) else '0';

    p_write : process(i_addr, i_read) begin
        if rising_edge(i_read) then
            case i_addr is
		when "000000" =>
		    w_seed <= "1001100";
		    w_iter <= 54;
		when "000001" =>
		    w_seed <= "1101001";
		    w_iter <= 86;
		when "000010" =>
		    w_seed <= "1110111";
		    w_iter <= 56;
		when "000011" =>
		    w_seed <= "0010100";
		    w_iter <= 9;
		when "000100" =>
		    w_seed <= "1111010";
		    w_iter <= 112;
		when "000101" =>
		    w_seed <= "0000101";
		    w_iter <= 13;
		when "000110" =>
		    w_seed <= "0111110";
		    w_iter <= 111;
		when "000111" =>
		    w_seed <= "0110011";
		    w_iter <= 9;
		when "001000" =>
		    w_seed <= "0110101";
		    w_iter <= 78;
		when "001001" =>
		    w_seed <= "0100011";
		    w_iter <= 123;
		when "001010" =>
		    w_seed <= "0110011";
		    w_iter <= 123;
		when "001011" =>
		    w_seed <= "0111001";
		    w_iter <= 126;
		when "001100" =>
		    w_seed <= "0101011";
		    w_iter <= 88;
		when "001101" =>
		    w_seed <= "1111100";
		    w_iter <= 75;
		when "001110" =>
		    w_seed <= "0110110";
		    w_iter <= 76;
		when "001111" =>
		    w_seed <= "1110101";
		    w_iter <= 30;
		when "010000" =>
		    w_seed <= "1111111";
		    w_iter <= 1;
		when "010001" =>
		    w_seed <= "0110111";
		    w_iter <= 61;
		when "010010" =>
		    w_seed <= "0010100";
		    w_iter <= 60;
		when "010011" =>
		    w_seed <= "0111101";
		    w_iter <= 109;
		when "010100" =>
		    w_seed <= "1011000";
		    w_iter <= 32;
		when "010101" =>
		    w_seed <= "1011010";
		    w_iter <= 95;
		when "010110" =>
		    w_seed <= "1001110";
		    w_iter <= 43;
		when "010111" =>
		    w_seed <= "1000111";
		    w_iter <= 28;
		when "011000" =>
		    w_seed <= "0010100";
		    w_iter <= 15;
		when "011001" =>
		    w_seed <= "1011000";
		    w_iter <= 7;
		when "011010" =>
		    w_seed <= "1011111";
		    w_iter <= 125;
		when "011011" =>
		    w_seed <= "1001010";
		    w_iter <= 38;
                when others =>
                    w_seed <= "0000000";
                    w_iter <= 0;
            end case;
            w_rst <= '0';
          elsif falling_edge(i_read) then
            w_rst <= '1';
        end if;
    end process p_write;

end architecture rtl;
