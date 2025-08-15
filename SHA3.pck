create or replace package SHA3
is 
    
  -- Parameters:
  --   p_message    - value to hash in types: raw, varchar2, lob
  --   p_type       - type of input: HEX|TXT
  --   p_lang       - for text input codepage of text
  --   p_out_length - for SHAKE - output length in bytes

  function keccak_224(p_message varchar2 character set any_cs,
                      p_type    varchar2 default 'HEX',
                      p_lang    varchar2 default 'AL32UTF8')
    return raw;  
    
  function keccak_224(p_message blob)
    return raw;
    
  function keccak_224(p_message clob character set any_cs, 
                      p_lang    varchar2 default 'AL32UTF8')
    return raw;

  function keccak_256(p_message varchar2 character set any_cs,
                      p_type    varchar2 default 'HEX',
                      p_lang    varchar2 default 'AL32UTF8')
    return raw; 
    
  function keccak_256(p_message blob)
    return raw;
    
  function keccak_256(p_message clob character set any_cs, 
                      p_lang    varchar2 default 'AL32UTF8')
    return raw;

  function keccak_384(p_message varchar2 character set any_cs,
                      p_type    varchar2 default 'HEX',
                      p_lang    varchar2 default 'AL32UTF8')
    return raw; 
    
  function keccak_384(p_message blob)
    return raw;
    
  function keccak_384(p_message clob character set any_cs, 
                      p_lang    varchar2 default 'AL32UTF8')
    return raw;

  function keccak_512(p_message varchar2 character set any_cs,
                      p_type    varchar2 default 'HEX',
                      p_lang    varchar2 default 'AL32UTF8')
    return raw; 
    
  function keccak_512(p_message blob)
    return raw;
    
  function keccak_512(p_message clob character set any_cs, 
                      p_lang    varchar2 default 'AL32UTF8')
    return raw;

  function sha3_224(p_message varchar2 character set any_cs,
                    p_type    varchar2 default 'HEX',
                    p_lang    varchar2 default 'AL32UTF8')
    return raw; 
    
  function sha3_224(p_message blob)
    return raw;
    
  function sha3_224(p_message clob character set any_cs, 
                    p_lang    varchar2 default 'AL32UTF8')
    return raw;

  function sha3_256(p_message varchar2 character set any_cs,
                    p_type    varchar2 default 'HEX',
                    p_lang    varchar2 default 'AL32UTF8')
    return raw; 
    
  function sha3_256(p_message blob)
    return raw;
    
  function sha3_256(p_message clob character set any_cs, 
                    p_lang    varchar2 default 'AL32UTF8')
    return raw;

  function sha3_384(p_message varchar2 character set any_cs,
                    p_type    varchar2 default 'HEX',
                    p_lang    varchar2 default 'AL32UTF8')
    return raw; 
    
  function sha3_384(p_message blob)
    return raw;
    
  function sha3_384(p_message clob character set any_cs, 
                    p_lang    varchar2 default 'AL32UTF8')
    return raw;

  function sha3_512(p_message varchar2 character set any_cs,
                    p_type    varchar2 default 'HEX',
                    p_lang    varchar2 default 'AL32UTF8')
    return raw; 
    
  function sha3_512(p_message blob)
    return raw;
    
  function sha3_512(p_message clob character set any_cs, 
                    p_lang    varchar2 default 'AL32UTF8')
    return raw;
    
  function shake_128(p_message    varchar2 character set any_cs,
                     p_out_length pls_integer default 32,
                     p_type       varchar2 default 'HEX',
                     p_lang       varchar2 default 'AL32UTF8')
    return raw; 
  
  function shake_128(p_message    blob,
                     p_out_length pls_integer default 32)
    return raw;    
  
  function shake_128(p_message clob character set any_cs,
                     p_out_length pls_integer default 32, 
                     p_lang    varchar2 default 'AL32UTF8')
    return raw; 
    
  function shake_256(p_message    varchar2 character set any_cs,
                     p_out_length pls_integer default 64,
                     p_type       varchar2 default 'HEX',
                     p_lang       varchar2 default 'AL32UTF8')
    return raw; 
  
  function shake_256(p_message    blob,
                     p_out_length pls_integer default 64)
    return raw;    
  
  function shake_256(p_message clob character set any_cs,
                     p_out_length pls_integer default 64, 
                     p_lang    varchar2 default 'AL32UTF8')
    return raw; 

  --------------------- PRIVATE -------------------------

  type lrotate_t      is table of varchar2(4) index by varchar2(4);
  type sponge_row_t   is varray(5) of raw(8);
  type sponge_t       is varray(25) of raw(8);
  type keccakf_cons_t is varray(24) of pls_integer;
  type keccakf_rndc_t is varray(24) of raw(8);

  raw0         constant raw(8) := hextoraw('0000000000000000');
  rawpadd      constant raw(8) := hextoraw('8000000000000000');
  keccakf_piln constant keccakf_cons_t := keccakf_cons_t(10, 07, 11, 17, 18, 03, 05, 16, 08, 21, 24, 04,
                                                         15, 23, 19, 13, 12, 02, 20, 14, 22, 09, 06, 01);
  keccakf_rotc constant keccakf_cons_t := keccakf_cons_t(01, 03, 06, 10, 15, 21, 28, 36, 45, 55, 02, 14,
                                                         27, 41, 56, 08, 25, 43, 62, 18, 39, 61, 20, 44);
  keccakf_rndc constant keccakf_rndc_t := keccakf_rndc_t(hextoraw('0000000000000001'), hextoraw('0000000000008082'), hextoraw('800000000000808a'),
                                                         hextoraw('8000000080008000'), hextoraw('000000000000808b'), hextoraw('0000000080000001'),
                                                         hextoraw('8000000080008081'), hextoraw('8000000000008009'), hextoraw('000000000000008a'),
                                                         hextoraw('0000000000000088'), hextoraw('0000000080008009'), hextoraw('000000008000000a'),
                                                         hextoraw('000000008000808b'), hextoraw('800000000000008b'), hextoraw('8000000000008089'),
                                                         hextoraw('8000000000008003'), hextoraw('8000000000008002'), hextoraw('8000000000000080'),
                                                         hextoraw('000000000000800a'), hextoraw('800000008000000a'), hextoraw('8000000080008081'),
                                                         hextoraw('8000000000008080'), hextoraw('0000000080000001'), hextoraw('8000000080008008'));

  lrotate_data lrotate_t;

end SHA3;
/

create or replace package body SHA3
is

  --------------------- PRIVATE ------------------------- 

  function rotleft(x raw, p_offset pls_integer)
    return raw
  as
    str_hex1 varchar2(16);
    str_hex2 varchar2(16);
    str_bin  varchar2(64);
    i        pls_integer;
  begin
    str_hex1 := rawtohex(x);

    for i in 1..16 loop
      str_bin := str_bin || lrotate_data(substr(str_hex1, i, 1));
    end loop;  

    str_bin := substr(str_bin, p_offset + 1) || substr(str_bin, 1, p_offset);

    i := 1;

    while i <= 64 loop
      str_hex2 := str_hex2 || lrotate_data(substr(str_bin, i, 4));
      i := i + 4;
    end loop;

    return hextoraw(str_hex2);  
  end rotleft;  

  procedure keccak_cycle(sponge in out nocopy sponge_t)
  as
    bc sponge_row_t := sponge_row_t(raw0, raw0, raw0, raw0, raw0);
    t  raw(8) := raw0;
  begin 
    for i in 1..24 loop  
      -- Theta
      for j in 1..5 loop
        bc(j) := utl_raw.bit_xor(sponge(j), utl_raw.bit_xor(sponge(j + 5), utl_raw.bit_xor(sponge(j + 10), utl_raw.bit_xor(sponge(j + 15), sponge(j + 20)))));
      end loop;

      for j in 0..4 loop
        PRAGMA INLINE (rotleft, 'YES');
        t := utl_raw.bit_xor(bc(mod(j + 4, 5) + 1), rotleft(bc(mod(j + 1, 5) + 1), 1));

        for k in 0..4 loop
          sponge(j + k * 5 + 1) := utl_raw.bit_xor(sponge(j + k * 5 + 1), t);
        end loop;
      end loop;
  
      -- Rho Pi
      t := sponge(2);

      for j in 1..24 loop
        bc(1) := sponge(keccakf_piln(j) + 1);
        PRAGMA INLINE (rotleft, 'YES');
        sponge(keccakf_piln(j) + 1) := rotleft(t, keccakf_rotc(j));
        t := bc(1);
      end loop;
  
      -- Chi
      for j in 0..4 loop
        for k in 1..5 loop
          bc(k) := sponge(j * 5 + k);
        end loop;

        for k in 1..5 loop
          sponge(j * 5 + k) := utl_raw.bit_xor(sponge(j * 5 + k), utl_raw.bit_and(utl_raw.bit_complement(bc(mod(k, 5) + 1)), bc(mod(k + 1, 5) + 1)));
        end loop;
      end loop;
  
      -- Iota
      sponge(1) := utl_raw.bit_xor(sponge(1), keccakf_rndc(i));
    end loop;
  end keccak_cycle;

  function keccak(p_msg_in     raw,
                  p_rsize      pls_integer,
                  p_delim      varchar2,
                  p_out_length pls_integer default 32)
    return raw
  as
    msg_length pls_integer;
    cnt        pls_integer;
    i          pls_integer;
    sponge     sponge_t := sponge_t(raw0, raw0, raw0, raw0, raw0,
                                    raw0, raw0, raw0, raw0, raw0,
                                    raw0, raw0, raw0, raw0, raw0,
                                    raw0, raw0, raw0, raw0, raw0,
                                    raw0, raw0, raw0, raw0, raw0);

    p_ret_value raw(32767);
  begin 
    msg_length := nvl(utl_raw.length(p_msg_in), 0);

    cnt := 0;
    i   := 1;

    if (msg_length > 0) then
      loop
        if (msg_length - cnt >= 8) then
          sponge(i) := utl_raw.bit_xor(sponge(i), utl_raw.reverse(utl_raw.substr(p_msg_in, cnt + 1, 8)));
        else
          sponge(i) := utl_raw.bit_xor(sponge(i), utl_raw.reverse(utl_raw.bit_xor(raw0, utl_raw.substr(p_msg_in, cnt + 1, msg_length - cnt))));
          exit;
        end if;

        if (mod(cnt + 8, p_rsize) = 0 and cnt + 8 <= msg_length) then
          PRAGMA INLINE (keccak_cycle, 'YES');
          keccak_cycle(sponge);
          i := 1;
        else
          i := i + 1;
        end if;

        exit when cnt + 8 >= msg_length;

        cnt := cnt + 8;
      end loop;
    end if;

    sponge(i)       := utl_raw.bit_xor(sponge(i), utl_raw.reverse(utl_raw.bit_xor(raw0, hextoraw(lpad(p_delim, mod(msg_length - cnt, 8) * 2 + 2, '0')))));
    sponge(p_rsize / 8) := utl_raw.bit_xor(sponge(p_rsize / 8), rawpadd); 

    PRAGMA INLINE (keccak_cycle, 'YES');
    keccak_cycle(sponge); 
    
    if (p_delim != '1F') then
      for j in 1..(200 - p_rsize) / 16 loop
        p_ret_value := p_ret_value || utl_raw.reverse(sponge(j));
      end loop;
      
      if (p_rsize = 144) then
        p_ret_value := utl_raw.substr(p_ret_value, 1, 28);  
      end if;
    else
      i := 1;  
      cnt := 0;  
    
      loop
        if (i > p_rsize / 8) then
          PRAGMA INLINE (keccak_cycle, 'YES');
          keccak_cycle(sponge);
          i := 1;   
        end if;
        
        if (p_out_length - cnt >= 8) then
          p_ret_value := p_ret_value || utl_raw.reverse(sponge(i));
        else
          p_ret_value := p_ret_value || utl_raw.substr(utl_raw.reverse(sponge(i)), 1, p_out_length - cnt);  
        
          exit;
        end if; 
        
        exit when cnt + 8 = p_out_length;
          
        i := i + 1;
        cnt := cnt + 8;
      end loop; 
    end if;

    return p_ret_value;
  end keccak;

  function keccak_blob(p_msg_in blob,
                       p_rsize  pls_integer,
                       p_delim  varchar2,
                       p_out_length pls_integer default 32)
    return raw
  as 
    raw_msg    raw(16000);
    lob_offset pls_integer := 1;
    msg_length pls_integer;
    raw_length pls_integer := 16000;
    cnt_raw    pls_integer;
    cnt        pls_integer;
    i          pls_integer;
    sponge     sponge_t := sponge_t(raw0, raw0, raw0, raw0, raw0,
                                    raw0, raw0, raw0, raw0, raw0,
                                    raw0, raw0, raw0, raw0, raw0,
                                    raw0, raw0, raw0, raw0, raw0,
                                    raw0, raw0, raw0, raw0, raw0);

    p_ret_value raw(32767);
  begin  
    cnt     := 0;  
    i       := 1;
    
    if (p_msg_in is not null) then  
      msg_length := dbms_lob.getlength(p_msg_in); 
       
      if (msg_length > 0) then  
        <<main_loop>>
        loop  
          cnt_raw := 0;
          
          begin
            dbms_lob.read(p_msg_in, raw_length, lob_offset, raw_msg);   
          exception
            when NO_DATA_FOUND then 
              exit;
          end;  
             
          loop
            if (raw_length - cnt_raw >= 8) then
              sponge(i) := utl_raw.bit_xor(sponge(i), utl_raw.reverse(utl_raw.substr(raw_msg, cnt_raw + 1, 8)));
            else
              sponge(i) := utl_raw.bit_xor(sponge(i), utl_raw.reverse(utl_raw.bit_xor(raw0, utl_raw.substr(raw_msg, cnt_raw + 1, raw_length - cnt_raw))));
              exit main_loop;
            end if;

            if (mod(cnt + 8, p_rsize) = 0 and cnt_raw + 8 <= raw_length) then
              PRAGMA INLINE (keccak_cycle, 'YES');
              keccak_cycle(sponge);
              i := 1;
            else
              i := i + 1;
            end if;

            exit when cnt_raw + 8 >= raw_length;

            cnt := cnt + 8;
            cnt_raw := cnt_raw + 8;
          end loop;  
          
          exit when raw_length < 16000;
          
          lob_offset := lob_offset + 16000;
        end loop; 
      end if;
    else
      msg_length := 0;
      cnt        := 0;  
    end if; 

    sponge(i)       := utl_raw.bit_xor(sponge(i), utl_raw.reverse(utl_raw.bit_xor(raw0, hextoraw(lpad(p_delim, mod(msg_length - cnt, 8) * 2 + 2, '0')))));
    sponge(p_rsize / 8) := utl_raw.bit_xor(sponge(p_rsize / 8), rawpadd);

    PRAGMA INLINE (keccak_cycle, 'YES');
    keccak_cycle(sponge);

    if (p_delim != '1F') then
      for j in 1..(200 - p_rsize) / 16 loop
        p_ret_value := p_ret_value || utl_raw.reverse(sponge(j));
      end loop;
      
      if (p_rsize = 144) then
        p_ret_value := utl_raw.substr(p_ret_value, 1, 28);  
      end if;
    else
      i := 1;  
      cnt := 0;  
    
      loop
        if (i > p_rsize / 8) then
          PRAGMA INLINE (keccak_cycle, 'YES');
          keccak_cycle(sponge);
          i := 1;   
        end if;
        
        if (p_out_length - cnt >= 8) then
          p_ret_value := p_ret_value || utl_raw.reverse(sponge(i));
        else
          p_ret_value := p_ret_value || utl_raw.substr(utl_raw.reverse(sponge(i)), 1, p_out_length - cnt);  
        
          exit;
        end if; 
        
        exit when cnt + 8 = p_out_length;
          
        i := i + 1;
        cnt := cnt + 8;
      end loop; 
    end if;

    return p_ret_value;
  end keccak_blob;

  --------------------- PUBLIC -------------------------

  function keccak_224(p_message varchar2 character set any_cs,
                      p_type    varchar2 default 'HEX',
                      p_lang    varchar2 default 'AL32UTF8')
    return raw
  as 
  begin  
    case upper(p_type)
      when 'HEX' then  
        return keccak(hextoraw(p_message), 144, '01'); 
      when 'TXT' then  
        if (nls_charset_id(p_lang) is null) then
          raise_application_error(-20002, 'Incorrect language');  
        end if;  
      
        return keccak(utl_i18n.string_to_raw(p_message, p_lang), 144, '01');  
      else
        raise_application_error(-20001, 'Incorrect type of message'); 
    end case; 
  end keccak_224;  
  
  function keccak_224(p_message blob)
    return raw
  as 
  begin 
    return keccak_blob(p_message, 144, '01'); 
  end keccak_224;  
  
  function keccak_224(p_message clob character set any_cs, 
                      p_lang    varchar2 default 'AL32UTF8')
    return raw
  as 
    p_blob         blob;
    msg_length     int;
    p_dest_offset  int := 1;
    p_src_offset   int := 1;
    p_lang_context int := dbms_lob.default_lang_ctx;
    p_warning      int;
  begin 
    if (p_message is not null) then  
      msg_length := dbms_lob.getlength(p_message); 
       
      if (msg_length > 0) then  
        if (nls_charset_id(p_lang) is null) then
          raise_application_error(-20002, 'Incorrect language');  
        end if;  
      
        dbms_lob.createtemporary(p_blob, true);  
        dbms_lob.convertToBlob(p_blob, p_message, msg_length, p_dest_offset, p_src_offset, nls_charset_id(p_lang), p_lang_context, p_warning);  
      end if;
    end if;
   
   return keccak_blob(p_blob, 144, '01'); 
  end keccak_224;  
  
  function keccak_256(p_message varchar2 character set any_cs,
                      p_type    varchar2 default 'HEX',
                      p_lang    varchar2 default 'AL32UTF8')
    return raw
  as 
  begin 
    case upper(p_type)
      when 'HEX' then  
        return keccak(hextoraw(p_message), 136, '01'); 
      when 'TXT' then    
        if (nls_charset_id(p_lang) is null) then
          raise_application_error(-20002, 'Incorrect language');  
        end if;  
      
        return keccak(utl_i18n.string_to_raw(p_message, p_lang), 136, '01');  
      else
        raise_application_error(-20001, 'Incorrect type of message'); 
    end case; 
  end keccak_256;    
  
  function keccak_256(p_message blob)
    return raw
  as 
  begin 
    return keccak_blob(p_message, 136, '01'); 
  end keccak_256;  
  
  function keccak_256(p_message clob character set any_cs, 
                      p_lang    varchar2 default 'AL32UTF8')
    return raw
  as 
    p_blob         blob;
    msg_length     int;
    p_dest_offset  int := 1;
    p_src_offset   int := 1;
    p_lang_context int := dbms_lob.default_lang_ctx;
    p_warning      int;
  begin 
    if (p_message is not null) then  
      msg_length := dbms_lob.getlength(p_message); 
       
      if (msg_length > 0) then  
        if (nls_charset_id(p_lang) is null) then
          raise_application_error(-20002, 'Incorrect language');  
        end if;  
      
        dbms_lob.createtemporary(p_blob, true);  
        dbms_lob.convertToBlob(p_blob, p_message, msg_length, p_dest_offset, p_src_offset, nls_charset_id(p_lang), p_lang_context, p_warning);  
      end if;
    end if;
   
   return keccak_blob(p_blob, 136, '01'); 
  end keccak_256;  
  
  function keccak_384(p_message varchar2 character set any_cs,
                      p_type    varchar2 default 'HEX',
                      p_lang    varchar2 default 'AL32UTF8')
    return raw
  as 
  begin 
    case upper(p_type)
      when 'HEX' then  
        return keccak(hextoraw(p_message), 104, '01'); 
      when 'TXT' then    
        if (nls_charset_id(p_lang) is null) then
          raise_application_error(-20002, 'Incorrect language');  
        end if;  
      
        return keccak(utl_i18n.string_to_raw(p_message, p_lang), 104, '01');  
      else
        raise_application_error(-20001, 'Incorrect type of message'); 
    end case; 
  end keccak_384;     
  
  function keccak_384(p_message blob)
    return raw
  as 
  begin 
    return keccak_blob(p_message, 104, '01'); 
  end keccak_384;   
  
  function keccak_384(p_message clob character set any_cs, 
                      p_lang    varchar2 default 'AL32UTF8')
    return raw
  as 
    p_blob         blob;
    msg_length     int;
    p_dest_offset  int := 1;
    p_src_offset   int := 1;
    p_lang_context int := dbms_lob.default_lang_ctx;
    p_warning      int;
  begin 
    if (p_message is not null) then  
      msg_length := dbms_lob.getlength(p_message); 
       
      if (msg_length > 0) then  
        if (nls_charset_id(p_lang) is null) then
          raise_application_error(-20002, 'Incorrect language');  
        end if;  
      
        dbms_lob.createtemporary(p_blob, true);  
        dbms_lob.convertToBlob(p_blob, p_message, msg_length, p_dest_offset, p_src_offset, nls_charset_id(p_lang), p_lang_context, p_warning);  
      end if;
    end if;
   
   return keccak_blob(p_blob, 104, '01'); 
  end keccak_384;  
  
  function keccak_512(p_message varchar2 character set any_cs,
                      p_type    varchar2 default 'HEX',
                      p_lang    varchar2 default 'AL32UTF8')
    return raw
  as 
  begin 
    case upper(p_type)
      when 'HEX' then  
        return keccak(hextoraw(p_message), 72, '01'); 
      when 'TXT' then    
        if (nls_charset_id(p_lang) is null) then
          raise_application_error(-20002, 'Incorrect language');  
        end if;  
      
        return keccak(utl_i18n.string_to_raw(p_message, p_lang), 72, '01');  
      else
        raise_application_error(-20001, 'Incorrect type of message'); 
    end case; 
  end keccak_512;    
  
  function keccak_512(p_message blob)
    return raw
  as 
  begin 
    return keccak_blob(p_message, 72, '01'); 
  end keccak_512;  
  
  function keccak_512(p_message clob character set any_cs, 
                      p_lang    varchar2 default 'AL32UTF8')
    return raw
  as 
    p_blob         blob;
    msg_length     int;
    p_dest_offset  int := 1;
    p_src_offset   int := 1;
    p_lang_context int := dbms_lob.default_lang_ctx;
    p_warning      int;
  begin 
    if (p_message is not null) then  
      msg_length := dbms_lob.getlength(p_message); 
       
      if (msg_length > 0) then  
        if (nls_charset_id(p_lang) is null) then
          raise_application_error(-20002, 'Incorrect language');  
        end if;  
      
        dbms_lob.createtemporary(p_blob, true);  
        dbms_lob.convertToBlob(p_blob, p_message, msg_length, p_dest_offset, p_src_offset, nls_charset_id(p_lang), p_lang_context, p_warning);  
      end if;
    end if;
   
   return keccak_blob(p_blob, 72, '01'); 
  end keccak_512;  

  function sha3_224(p_message varchar2 character set any_cs,
                    p_type    varchar2 default 'HEX',
                    p_lang    varchar2 default 'AL32UTF8')
    return raw
  as 
  begin 
    case upper(p_type)
      when 'HEX' then  
        return keccak(hextoraw(p_message), 144, '06'); 
      when 'TXT' then    
        if (nls_charset_id(p_lang) is null) then
          raise_application_error(-20002, 'Incorrect language');  
        end if;  
      
        return keccak(utl_i18n.string_to_raw(p_message, p_lang), 144, '06');  
      else
        raise_application_error(-20001, 'Incorrect type of message'); 
    end case; 
  end sha3_224;      
  
  function sha3_224(p_message blob)
    return raw
  as 
  begin 
    return keccak_blob(p_message, 144, '06'); 
  end sha3_224;  
  
  function sha3_224(p_message clob character set any_cs, 
                    p_lang    varchar2 default 'AL32UTF8')
    return raw
  as 
    p_blob         blob;
    msg_length     int;
    p_dest_offset  int := 1;
    p_src_offset   int := 1;
    p_lang_context int := dbms_lob.default_lang_ctx;
    p_warning      int;
  begin 
    if (p_message is not null) then  
      msg_length := dbms_lob.getlength(p_message); 
       
      if (msg_length > 0) then  
        if (nls_charset_id(p_lang) is null) then
          raise_application_error(-20002, 'Incorrect language');  
        end if;  
      
        dbms_lob.createtemporary(p_blob, true);  
        dbms_lob.convertToBlob(p_blob, p_message, msg_length, p_dest_offset, p_src_offset, nls_charset_id(p_lang), p_lang_context, p_warning);  
      end if;
    end if;
   
   return keccak_blob(p_blob, 144, '06'); 
  end sha3_224;  

  function sha3_256(p_message varchar2 character set any_cs,
                    p_type    varchar2 default 'HEX',
                    p_lang    varchar2 default 'AL32UTF8')
    return raw
  as 
  begin 
    case upper(p_type)
      when 'HEX' then  
        return keccak(hextoraw(p_message), 136, '06'); 
      when 'TXT' then    
        if (nls_charset_id(p_lang) is null) then
          raise_application_error(-20002, 'Incorrect language');  
        end if;  
      
        return keccak(utl_i18n.string_to_raw(p_message, p_lang), 136, '06');  
      else
        raise_application_error(-20001, 'Incorrect type of message'); 
    end case; 
  end sha3_256;      
  
  function sha3_256(p_message blob)
    return raw
  as 
  begin 
    return keccak_blob(p_message, 136, '06'); 
  end sha3_256;  
  
  function sha3_256(p_message clob character set any_cs, 
                    p_lang    varchar2 default 'AL32UTF8')
    return raw
  as 
    p_blob         blob;
    msg_length     int;
    p_dest_offset  int := 1;
    p_src_offset   int := 1;
    p_lang_context int := dbms_lob.default_lang_ctx;
    p_warning      int;
  begin 
    if (p_message is not null) then  
      msg_length := dbms_lob.getlength(p_message); 
       
      if (msg_length > 0) then  
        if (nls_charset_id(p_lang) is null) then
          raise_application_error(-20002, 'Incorrect language');  
        end if;  
      
        dbms_lob.createtemporary(p_blob, true);  
        dbms_lob.convertToBlob(p_blob, p_message, msg_length, p_dest_offset, p_src_offset, nls_charset_id(p_lang), p_lang_context, p_warning);  
      end if;
    end if;
   
   return keccak_blob(p_blob, 136, '06'); 
  end sha3_256;  

  function sha3_384(p_message varchar2 character set any_cs,
                    p_type    varchar2 default 'HEX',
                    p_lang    varchar2 default 'AL32UTF8')
    return raw
  as 
  begin 
    case upper(p_type)
      when 'HEX' then  
        return keccak(hextoraw(p_message), 104, '06'); 
      when 'TXT' then    
        if (nls_charset_id(p_lang) is null) then
          raise_application_error(-20002, 'Incorrect language');  
        end if;  
      
        return keccak(utl_i18n.string_to_raw(p_message, p_lang), 104, '06');  
      else
        raise_application_error(-20001, 'Incorrect type of message'); 
    end case; 
  end sha3_384;      
  
  function sha3_384(p_message blob)
    return raw
  as 
  begin 
    return keccak_blob(p_message, 104, '06'); 
  end sha3_384;   
  
  function sha3_384(p_message clob character set any_cs, 
                    p_lang    varchar2 default 'AL32UTF8')
    return raw
  as 
    p_blob         blob;
    msg_length     int;
    p_dest_offset  int := 1;
    p_src_offset   int := 1;
    p_lang_context int := dbms_lob.default_lang_ctx;
    p_warning      int;
  begin 
    if (p_message is not null) then  
      msg_length := dbms_lob.getlength(p_message); 
       
      if (msg_length > 0) then  
        if (nls_charset_id(p_lang) is null) then
          raise_application_error(-20002, 'Incorrect language');  
        end if;  
      
        dbms_lob.createtemporary(p_blob, true);  
        dbms_lob.convertToBlob(p_blob, p_message, msg_length, p_dest_offset, p_src_offset, nls_charset_id(p_lang), p_lang_context, p_warning);  
      end if;
    end if;
   
   return keccak_blob(p_blob, 104, '06'); 
  end sha3_384;  

  function sha3_512(p_message varchar2 character set any_cs,
                    p_type    varchar2 default 'HEX',
                    p_lang    varchar2 default 'AL32UTF8')
    return raw
  as 
  begin 
    case upper(p_type)
      when 'HEX' then  
        return keccak(hextoraw(p_message), 72, '06'); 
      when 'TXT' then    
        if (nls_charset_id(p_lang) is null) then
          raise_application_error(-20002, 'Incorrect language');  
        end if;  
      
        return keccak(utl_i18n.string_to_raw(p_message, p_lang), 72, '06');  
      else
        raise_application_error(-20001, 'Incorrect type of message'); 
    end case; 
  end sha3_512;  
  
  function sha3_512(p_message blob)
    return raw
  as 
  begin 
    return keccak_blob(p_message, 72, '06'); 
  end sha3_512;    
  
  function sha3_512(p_message clob character set any_cs, 
                    p_lang    varchar2 default 'AL32UTF8')
    return raw
  as 
    p_blob         blob;
    msg_length     int;
    p_dest_offset  int := 1;
    p_src_offset   int := 1;
    p_lang_context int := dbms_lob.default_lang_ctx;
    p_warning      int;
  begin 
    if (p_message is not null) then  
      msg_length := dbms_lob.getlength(p_message); 
       
      if (msg_length > 0) then  
        if (nls_charset_id(p_lang) is null) then
          raise_application_error(-20002, 'Incorrect language');  
        end if;  
      
        dbms_lob.createtemporary(p_blob, true);  
        dbms_lob.convertToBlob(p_blob, p_message, msg_length, p_dest_offset, p_src_offset, nls_charset_id(p_lang), p_lang_context, p_warning);  
      end if;
    end if;
   
   return keccak_blob(p_blob, 72, '06'); 
  end sha3_512;  
  
  function shake_128(p_message    varchar2 character set any_cs,
                     p_out_length pls_integer default 32,
                     p_type       varchar2 default 'HEX',
                     p_lang       varchar2 default 'AL32UTF8')
    return raw
  as 
  begin 
    case upper(p_type)
      when 'HEX' then  
        return keccak(hextoraw(p_message), 168, '1F', p_out_length); 
      when 'TXT' then    
        if (nls_charset_id(p_lang) is null) then
          raise_application_error(-20002, 'Incorrect language');  
        end if;  
      
        return keccak(utl_i18n.string_to_raw(p_message, p_lang), 168, '1F', p_out_length);  
      else
        raise_application_error(-20001, 'Incorrect type of message'); 
    end case; 
  end shake_128; 
  
  function shake_128(p_message    blob,
                     p_out_length pls_integer default 32)
    return raw
  as 
  begin 
    return keccak_blob(p_message, 168, '1F', p_out_length); 
  end shake_128;    
  
  function shake_128(p_message clob character set any_cs,
                     p_out_length pls_integer default 32, 
                     p_lang    varchar2 default 'AL32UTF8')
    return raw
  as 
    p_blob         blob;
    msg_length     int;
    p_dest_offset  int := 1;
    p_src_offset   int := 1;
    p_lang_context int := dbms_lob.default_lang_ctx;
    p_warning      int;
  begin 
    if (p_message is not null) then  
      msg_length := dbms_lob.getlength(p_message); 
       
      if (msg_length > 0) then  
        if (nls_charset_id(p_lang) is null) then
          raise_application_error(-20002, 'Incorrect language');  
        end if;  
      
        dbms_lob.createtemporary(p_blob, true);  
        dbms_lob.convertToBlob(p_blob, p_message, msg_length, p_dest_offset, p_src_offset, nls_charset_id(p_lang), p_lang_context, p_warning);  
      end if;
    end if;
   
   return keccak_blob(p_blob, 168, '1F', p_out_length); 
  end shake_128; 

  function shake_256(p_message    varchar2 character set any_cs,
                     p_out_length pls_integer default 64,
                     p_type       varchar2 default 'HEX',
                     p_lang       varchar2 default 'AL32UTF8')
    return raw
  as 
  begin 
    case upper(p_type)
      when 'HEX' then  
        return keccak(hextoraw(p_message), 136, '1F', p_out_length); 
      when 'TXT' then    
        if (nls_charset_id(p_lang) is null) then
          raise_application_error(-20002, 'Incorrect language');  
        end if;  
      
        return keccak(utl_i18n.string_to_raw(p_message, p_lang), 136, '1F', p_out_length);  
      else
        raise_application_error(-20001, 'Incorrect type of message'); 
    end case; 
  end shake_256; 
  
  function shake_256(p_message    blob,
                     p_out_length pls_integer default 64)
    return raw
  as 
  begin 
    return keccak_blob(p_message, 136, '1F', p_out_length); 
  end shake_256;    
  
  function shake_256(p_message clob character set any_cs,
                     p_out_length pls_integer default 64, 
                     p_lang    varchar2 default 'AL32UTF8')
    return raw
  as 
    p_blob         blob;
    msg_length     int;
    p_dest_offset  int := 1;
    p_src_offset   int := 1;
    p_lang_context int := dbms_lob.default_lang_ctx;
    p_warning      int;
  begin 
    if (p_message is not null) then  
      msg_length := dbms_lob.getlength(p_message); 
       
      if (msg_length > 0) then  
        if (nls_charset_id(p_lang) is null) then
          raise_application_error(-20002, 'Incorrect language');  
        end if;  
      
        dbms_lob.createtemporary(p_blob, true);  
        dbms_lob.convertToBlob(p_blob, p_message, msg_length, p_dest_offset, p_src_offset, nls_charset_id(p_lang), p_lang_context, p_warning);  
      end if;
    end if;
   
   return keccak_blob(p_blob, 136, '1F', p_out_length); 
  end shake_256; 

begin
  lrotate_data('0') := '0000';
  lrotate_data('1') := '0001';
  lrotate_data('2') := '0010';
  lrotate_data('3') := '0011';
  lrotate_data('4') := '0100';
  lrotate_data('5') := '0101';
  lrotate_data('6') := '0110';
  lrotate_data('7') := '0111';
  lrotate_data('8') := '1000';
  lrotate_data('9') := '1001';
  lrotate_data('A') := '1010';
  lrotate_data('B') := '1011';
  lrotate_data('C') := '1100';
  lrotate_data('D') := '1101';
  lrotate_data('E') := '1110';
  lrotate_data('F') := '1111';
  lrotate_data('0000') := '0';
  lrotate_data('0001') := '1';
  lrotate_data('0010') := '2';
  lrotate_data('0011') := '3';
  lrotate_data('0100') := '4';
  lrotate_data('0101') := '5';
  lrotate_data('0110') := '6';
  lrotate_data('0111') := '7';
  lrotate_data('1000') := '8';
  lrotate_data('1001') := '9';
  lrotate_data('1010') := 'A';
  lrotate_data('1011') := 'B';
  lrotate_data('1100') := 'C';
  lrotate_data('1101') := 'D';
  lrotate_data('1110') := 'E';
  lrotate_data('1111') := 'F';
end SHA3;
/
